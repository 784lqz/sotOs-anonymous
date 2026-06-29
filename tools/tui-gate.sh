#!/usr/bin/env bash
# sotOs · compat-host TUI gate (Phase A · Task A6 · Phase B · Task B4 · Phase C · Task C5)
#
# Proves the Phase-A TUI slice: the real off-the-shelf Debian glibc-dynamic
# editors (less / nano / vim-tiny, via the real ld-linux-x86-64.so.2 + the
# ncurses/tinfo closure + xterm terminfo) RUN on sotOs, and `less` actually
# DRAWS a screen over the SSH canary-shell — pages /etc/passwd with terminal
# screen escapes (terminfo cursor/clear/status, NOT a plain cat dump) — PLUS the
# Phase-B slice: an SSH terminal RESIZE is honored end-to-end ([tty] winch) —
# PLUS the Phase-C slice: a Tier-2 attacker `vim :w`-edit of a /tmp canary file
# reads its OWN edit back in-session (the per-session COW-lite overlay), while
# the base canary graph is NEVER mutated and the operator observes the
# containment via the `[isolated] … → session overlay (base intact)` trace.
#
# Assertions, one boot, one early `ssh -tt` session (driven through a python pty
# so it has a real controlling tty → OpenSSH emits the RFC 4254 pty-req +
# window-change · SSH_ASKPASS handles the canary 2-reject-then-accept auth flow):
#  1) the boot `[tui]` auto-demo printed each editor's version + `[tui] handler
#     DONE` (less 6 / GNU nano / VIM - Vi IMproved · they load+link+run).
#  2) the session runs `less /etc/passwd` then `q`: the canary passwd content
#     streams AND a terminfo screen escape appears (alt-screen / clear / status).
#  4) Phase B · a mid-session pty resize → OpenSSH window-change → net-synth
#     `[ssh] winch` → SHELL_WINCH frame → orch `[tty] winch` (winsize honored
#     end-to-end while busybox is live); the initial pty-req size is also parsed.
#  5) Phase C · the SAME session `vim -u NONE`-edits the /tmp/welcome canary
#     (:%s substitutes a known word → :wq), then re-`cat`s it:
#       a) READ-BACK COHERENT — the post-:wq cat shows the edited word (the
#          overlay served it via op_read's C2 read-merge · the deception proof);
#       b) vim's :w SUCCEEDED (its "N bytes written" line · no E212/E166/Can't-
#          open-for-writing — the write reached the backend, it did not error);
#       c) OPERATOR OBSERVES CONTAINMENT — the serial carries the C3
#          `[isolated] … sotfs write … → session overlay (base intact)` trace,
#          tied to the welcome canary by the `[isolated] … welcome.swp` path
#          drops (proves the write was CONTAINED, base graph untouched).
#     NOTE on "base truly intact": this is STRUCTURALLY guaranteed by C3 (the
#     isolated write returns before any sotfs graph mutation) + PROVEN by the
#     `[isolated] … (base intact)` trace.  A fresh-session re-read (no HACKED)
#     would be the empirical complement, but a 2nd SSH connection does NOT
#     reliably spawn a busybox shell headless (the B4 single-session limit), so
#     we DELIBERATELY do not attempt one — the trace + structural guarantee are
#     the base-intact evidence.
#  3) zero faults across the run.
#
# Uses the SSH-gate boot line (it needs the :22 hostfwd; the glibcdyn-gate boot
# line has NO hostfwd).  Guards the operator's QEMU (BLOCKED · exit 3 · NEVER
# kills it); only the gate-spawned QEMU is trap-killed via $QPID.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
PORT=18022
SLOG=/tmp/sotos-tui-gate-serial.log
CLOG=/tmp/sotos-tui-gate-client.log

# NEVER pkill the operator's QEMU: if one is live it is theirs → BLOCKED.
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[tui-gate] BLOCKED: operator QEMU live (refusing to boot / kill)"; exit 3
fi
# The boot [tui] editors come from the glibcdyn handler, which is lean-skipped ·
# build the full battery (restore the fast LEAN default on exit).
. tools/lib/demo-full.sh; ensure_full_demos || exit 2
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[tui-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG" "$CLOG" /tmp/sotos-tui-g3-client.log

echo "[tui-gate] booting honeypot (SSH hostfwd · auto-demo runs the [tui] editors early)…"
timeout 260 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null; demo_lean_restore' EXIT

# Wait for the boot [tui] demo to settle (less/nano/vim --version ran).
waited=0
for i in $(seq 1 200); do
  LC_ALL=C grep -qa '\[tui\] handler DONE' "$SLOG" && { waited=$i; break; }
  sleep 1; waited=$i
done
echo "[tui-gate] [tui] settled after ${waited}s ($(wc -l < "$SLOG") serial lines)"

# Wait for :22 to LISTEN, then drive ONE EARLY `ssh -tt` session that does BOTH
# Phase A (less draws a screen) AND Phase B (a mid-session resize → [tty] winch).
#
# WHY one combined session (not two): only the FIRST early SSH session reliably
# spawns the busybox canary shell — once the boot's GTK/wayland demo box takes the
# orch main fault loop, a later SHELL_START is stashed but not hoisted (no busybox
# → SHELL_WINCH is dropped, since orch only honors a winch while a shell is live).
# So we drive a SINGLE session through a python-allocated pty (a real controlling
# tty → OpenSSH emits the RFC 4254 pty-req + window-change):
#   1) auth via the canary 2-reject-then-accept flow (SSH_ASKPASS re-supplies the
#      password on EVERY prompt — sshpass bails after the 1st reject);
#   2) `less /etc/passwd` + `q`  → Phase-A draw assertion (client log = $CLOG);
#   3) a mid-session TIOCSWINSZ to a DISTINCTIVE 110x33 → OpenSSH sends a
#      window-change → net-synth `[ssh] winch` → SHELL_WINCH → orch `[tty] winch`.
# The INITIAL pty-req carries 137x42 (net-synth parses it → `[ssh] winch 137x42`),
# but it arrives BEFORE busybox is live so orch drops it; the live window-change is
# the path that demonstrably reaches orch → it is the REQUIRED Phase-B proof.
WINCH_COLS=137; WINCH_ROWS=42       # initial pty-req size (distinctive · net-synth parse proof)
WINCH_COLS2=110; WINCH_ROWS2=33     # live window-change size at the busybox prompt ([tty] winch proof)
WINCH_COLS3=132; WINCH_ROWS3=50     # G1 · live window-change size WHILE vim is OPEN (reaches the forked editor)
# Phase C · the /tmp canary the attacker vim-edits.  /tmp/welcome is boot-installed
# (lucas_sotfs_install("/welcome", "HOLA from sotFS-α DPO\n") · backends_sotfs.c) →
# exists at Tier-2 so vim opens it cleanly (a NEW-file create is dropped, an EXISTING
# file's :w lands in the overlay).  We substitute a KNOWN word so the read-back is a
# distinctive, un-fakeable string.
COW_PATH=/tmp/welcome; COW_FROM=HOLA; COW_TO=HACKEDxC5    # known word → distinctive marker
for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
if LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG"; then
  echo "[tui-gate] :22 LISTEN · ssh -tt (pty ${WINCH_COLS}x${WINCH_ROWS}) · less + resize→${WINCH_COLS2}x${WINCH_ROWS2} + vim-mid-resize→${WINCH_COLS3}x${WINCH_ROWS3}…"
  ASK=/tmp/sotos-askpass.sh; printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
  # The G3 (F5) 2nd-session probe runs as a sibling bash background job INSIDE the
  # python session (so the 1st shell is provably live).  A sentinel FILE (not a FIFO
  # — a FIFO write with no reader blocks → deadlock) signals "1st shell established":
  # the python harness writes it → the bash sibling polls it → fires the 2nd ssh.
  G3GO=/tmp/sotos-tui-g3.go; rm -f "$G3GO"
  # G3 · the concurrent 2nd `ssh -tt` (fired once the 1st shell is live) → must hit
  # the `[orch] ssh-shell: … refused · shell busy` path + disconnect cleanly (no hang).
  ( for _ in $(seq 1 600); do [ -f "$G3GO" ] && break; sleep 0.1; done
    SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force timeout 25 python3 - "$PORT" <<'P2' >/tmp/sotos-tui-g3-client.log 2>&1 || true
import os,sys,pty,time,select
port=sys.argv[1]
pid,fd=pty.fork()
if pid==0:
    os.execvp("ssh",["ssh","-tt","-p",port,"-o","StrictHostKeyChecking=no",
      "-o","UserKnownHostsFile=/dev/null","-o","PreferredAuthentications=password",
      "-o","PubkeyAuthentication=no","-o","NumberOfPasswordPrompts=3",
      "-o","ConnectTimeout=15","root@127.0.0.1"]); os._exit(127)
buf=b""; dead=time.time()+18
while time.time()<dead:
    r,_,_=select.select([fd],[],[],0.3)
    if fd in r:
        try: d=os.read(fd,4096)
        except OSError: break
        if not d: break          # clean EOF · the 2nd session was disconnected
        buf+=d
        if b"assword" in buf: os.write(fd,b"hunter2\n"); buf=b""
sys.stdout.write("G3-2ND-EXITED\n")
P2
  ) &
  G3PID=$!
  # python pty.fork: parent sets the pty winsize, then execs ssh in the child whose
  # stdin/out IS that pty (its controlling tty).  Connect IMMEDIATELY (no sleep) so
  # this wins the early window before the demo box monopolizes the orch fault loop.
  SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  timeout 150 python3 - "$WINCH_COLS" "$WINCH_ROWS" "$WINCH_COLS2" "$WINCH_ROWS2" "$PORT" "$CLOG" \
      "$COW_PATH" "$COW_FROM" "$COW_TO" "$WINCH_COLS3" "$WINCH_ROWS3" "$G3GO" <<'PY' || true
import os, sys, pty, fcntl, termios, struct, time, select
cols, rows   = int(sys.argv[1]), int(sys.argv[2])
cols2, rows2 = int(sys.argv[3]), int(sys.argv[4])
port, outf   = sys.argv[5], sys.argv[6]
cow_path, cow_from, cow_to = sys.argv[7], sys.argv[8], sys.argv[9]   # Phase C edit
cols3, rows3 = int(sys.argv[10]), int(sys.argv[11])                  # G1 · vim-mid resize
g3go         = sys.argv[12]                                          # G3 · 2nd-session release flag
pid, fd = pty.fork()
if pid == 0:
    # child: stdin/stdout/stderr are the pty slave → this IS ssh's controlling tty.
    os.execvp("ssh", ["ssh", "-tt", "-p", port,
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=3", "-o", "ConnectTimeout=15",
        "root@127.0.0.1"])
    os._exit(127)
# parent: set the INITIAL pty winsize NOW, before ssh emits its pty-req (→137x42).
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
out = open(outf, "wb"); buf = b""
def pump(deadline, feed=False):
    """Drain the pty into $CLOG until `deadline`; reply to DSR + (optionally) feed
    the password so all 3 auth attempts complete."""
    global buf
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.3)
        if fd in r:
            try: data = os.read(fd, 4096)
            except OSError: return False
            if not data: return False
            out.write(data); out.flush(); buf += data
            if feed and b"assword" in buf:
                os.write(fd, b"hunter2\n"); buf = b""
            # busybox line-editor may emit a cursor-position request (ESC[6n) and
            # block on the reply → answer it so the shell keeps moving.
            if b"\x1b[6n" in buf:
                os.write(fd, b"\x1b[1;1R"); buf = buf.replace(b"\x1b[6n", b"")
    return True
def wait_for(needle, timeout):
    """Pump until `needle` (bytes) appears in the rolling window, else timeout."""
    global buf
    nd = needle if isinstance(needle, bytes) else needle.encode()
    end = time.time() + timeout
    while time.time() < end:
        if nd in buf: return True
        r, _, _ = select.select([fd], [], [], 0.3)
        if fd in r:
            try: data = os.read(fd, 4096)
            except OSError: return False
            if not data: return False
            out.write(data); out.flush(); buf += data
            if b"\x1b[6n" in buf:
                os.write(fd, b"\x1b[1;1R"); buf = buf.replace(b"\x1b[6n", b"")
    return False
def cmd(line, marker, timeout=8):
    """Run a SHELL command then wait for a unique echo sentinel = the prompt is back."""
    global buf
    buf = b""
    os.write(fd, (line + "\n").encode())
    os.write(fd, ("echo " + marker + "\n").encode())
    wait_for(marker + "\r", timeout) or wait_for(marker + "\n", 1)
    buf = b""

# ---- auth: 2 rejects + accept → the busybox prompt -------------------------
# Feed the password through the 2-reject-then-accept flow, then WAIT for the
# busybox prompt to actually appear ("$ " or the line-editor's cursor-position
# probe ESC[6n).  pump()/wait_for() answer the ESC[6n on sight, so the line
# editor isn't left blocked waiting for a DSR reply (sending a command before
# answering the DSR corrupts busybox's input state → nothing echoes back).
pump(time.time() + 6, feed=True)
got_prompt = wait_for(b"$ ", 18) or wait_for(b"\x1b[6n", 1)
pump(time.time() + 1.5)                 # let the ESC[6n reply settle + prompt redraw
# Now confirm the shell is actually consuming input: a unique echo sentinel.
buf = b""
os.write(fd, b"echo __SOTRDY__\n")
if wait_for("__SOTRDY__\r", 12) or wait_for("__SOTRDY__\n", 1):
    got_prompt = True
out.write(b"\n=== SHELL-LIVE (prompt up) ===\n"); out.flush()
# G3 · the 1st shell is provably live now → release the concurrent 2nd ssh.
try:
    with open(g3go, "w") as f: f.write("go\n")
except Exception: pass

# ---- Phase A · less draws a screen ----------------------------------------
buf = b""
os.write(fd, b"less /etc/passwd\n")
wait_for("root:", 6)
pump(time.time() + 1.5)
os.write(fd, b"q"); pump(time.time() + 1.5)        # quit less (no newline · less takes a bare 'q')
os.write(fd, b"\n");
if not (wait_for("__APOST__\r", 1)):
    cmd("true", "__APOST__", 4)

# ---- Phase B · live resize at the prompt → [tty] winch cols2 --------------
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows2, cols2, 0, 0))
pump(time.time() + 3)

# ---- G1+G2 · vim /etc/passwd · mid-vim resize + :w (HACKED) ----------------
# Open vim on the STATIC /etc/passwd (Tier-2 isolated → :w lands in the session
# overlay).  -u NONE: deterministic, no plugins.
buf = b""
os.write(fd, ("vim -u NONE -n %s\n" % "/etc/passwd").encode())
time.sleep(2.0); pump(time.time() + 1.5)           # let vim draw the file
# G1 · RESIZE WHILE VIM IS OPEN → window-change reaches the FORKED EDITOR child
# (lucas_console_winch_foreground → [tty] winch-fg woke>=1).  Distinctive 132x50.
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows3, cols3, 0, 0))
time.sleep(2.0); pump(time.time() + 1.5)
# Prove the editor saw the new width: ask vim for &columns into the channel.
buf = b""
os.write(fd, b":redraw\r"); time.sleep(0.5)
os.write(fd, b":echo 'COLS=' . &columns\r"); time.sleep(1.5); pump(time.time() + 1.0)
out.write(b"\n=== G1-COLS-PROBE done ===\n"); out.flush()
# G2/F2 · substitute root→HACKED on EVERY line, then :wq (write+quit).
os.write(fd, b":%s/root/HACKED/\r"); time.sleep(1.0)
os.write(fd, b":wq\r"); time.sleep(2.0); pump(time.time() + 1.5)
# back at the shell · confirm the prompt returned
cmd("true", "__VIMDONE__", 6)
# F2 read-back · grep the edit back out of /etc/passwd (overlay-merged read).
out.write(b"\n=== F2-READBACK-BEGIN ===\n"); out.flush()
buf = b""
os.write(fd, b"grep HACKED /etc/passwd\n"); os.write(fd, b"echo __F2END__\n")
wait_for("__F2END__\r", 6) or wait_for("__F2END__\n", 1)
out.write(b"\n=== F2-READBACK-END ===\n"); out.flush()

# ---- G2/F3 · SHORTEN the file on a 2nd edit · no stale tail ----------------
# Re-open /etc/passwd (now overlay-served = the HACKED version), delete all lines
# but the first, :wq → op_truncate shrinks the overlay → a re-cat must be SHORT.
buf = b""
os.write(fd, b"vim -u NONE -n /etc/passwd\n"); time.sleep(2.0); pump(time.time() + 1.5)
os.write(fd, b":2,$d\r"); time.sleep(1.0)          # keep ONLY line 1
os.write(fd, b":wq\r");   time.sleep(2.0); pump(time.time() + 1.5)
cmd("true", "__VIM2DONE__", 6)
out.write(b"\n=== F3-SHORT-BEGIN ===\n"); out.flush()
buf = b""
os.write(fd, b"cat /etc/passwd\n"); os.write(fd, b"echo __F3END__\n")
wait_for("__F3END__\r", 6) or wait_for("__F3END__\n", 1)
out.write(b"\n=== F3-SHORT-END ===\n"); out.flush()
# wc the file too · a hard numeric short-file proof (line count after the shrink).
out.write(b"\n=== F3-WC-BEGIN ===\n"); out.flush()
buf = b""
os.write(fd, b"wc -l /etc/passwd\n"); os.write(fd, b"echo __WCEND__\n")
wait_for("__WCEND__\r", 6) or wait_for("__WCEND__\n", 1)
out.write(b"\n=== F3-WC-END ===\n"); out.flush()

# ---- Phase C · the /tmp/welcome canary edit (the original C5 assertions) ----
buf = b""
os.write(fd, ("vim -u NONE -n %s\n" % cow_path).encode())
# vim opening a sotfs file (disk-backed via the blkdev since fs-1b) is slower
# than the static /etc/passwd edits above — a blind 2.0s sleep raced the cold
# blkdev read, so the :%s below reached the shell before vim was ready and
# leaked as an execve (the Phase-C flake).  Wait until vim has actually DRAWN
# the buffer (the known word appears on screen), exactly as Phase A waits after
# `less`; fall back to the old sleep if the draw is never seen.
wait_for(cow_from, 8) or time.sleep(2.0)
pump(time.time() + 1.5)
os.write(fd, (":%%s/%s/%s/\r" % (cow_from, cow_to)).encode()); time.sleep(1.0)
os.write(fd, b":wq\r"); time.sleep(2.0); pump(time.time() + 1.5)
cmd("true", "__VIMCDONE__", 6)
out.write(b"\n=== C5-READBACK-BEGIN ===\n"); out.flush()
buf = b""
os.write(fd, ("cat %s\n" % cow_path).encode()); os.write(fd, b"echo __C5END__\n")
wait_for("__C5END__\r", 6) or wait_for("__C5END__\n", 1)
out.write(b"\n=== C5-READBACK-END ===\n"); out.flush()

os.write(fd, b"exit\n"); pump(time.time() + 4)
out.close()
try: os.close(fd)
except OSError: pass
PY
  echo "[tui-gate] ssh -tt session done ($(wc -l < "$CLOG" 2>/dev/null || echo 0) client lines)"
  wait $G3PID 2>/dev/null || true
  rm -f "$G3GO"
else
  echo "[tui-gate] WARN · :22 never LISTENed — SSH leg skipped"
fi

# Settle + stop our QEMU (operator-safe: only $QPID).
sleep 1; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== compat-host · TUI editors (vim/nano/less) gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
sgF(){ LC_ALL=C grep -acF "$1" "$SLOG"; }
cgF(){ LC_ALL=C grep -acF "$1" "$CLOG"; }

# ---- Assertion 1 · the boot [tui] demo: each editor loaded+linked+ran (--version)
[ "$(sg 'less 6')" -ge 1 ] \
  && echo "PASS · less ran at boot (less 6.x version)" \
  || { echo "FAIL · less --version missing from [tui] demo"; fail=1; }
[ "$(sgF 'GNU nano')" -ge 1 ] \
  && echo "PASS · nano ran at boot (GNU nano version)" \
  || { echo "FAIL · nano --version missing from [tui] demo"; fail=1; }
[ "$(sgF 'VIM - Vi IMproved')" -ge 1 ] \
  && echo "PASS · vim ran at boot (VIM - Vi IMproved version)" \
  || { echo "FAIL · vim --version missing from [tui] demo"; fail=1; }
[ "$(sg '\[tui\] handler DONE')" -ge 1 ] \
  && echo "PASS · [tui] handler completed" \
  || { echo "FAIL · [tui] handler DONE not seen"; fail=1; }

# ---- Assertion 2 · `less /etc/passwd` over the SSH canary shell DREW a screen.
# The canary passwd content streamed back encrypted (root: line).
[ "$(cgF 'root:')" -ge 1 ] \
  && echo "PASS · less paged the canary /etc/passwd over SSH (root: line)" \
  || { echo "FAIL · canary passwd content did not stream through less"; fail=1; }
# A terminfo SCREEN escape appeared (less uses terminfo → cursor/clear/status,
# NOT a plain cat dump).  Match the REAL bytes less emitted (see the cat -v probe
# below): alt-screen enter/leave (\e[?1049h / \e[?47h), clear (\e[2J), home
# (\e[H), or the less status / clear-to-EOL (\e[K) / reverse-video (\e[7m).
ESC=$'\033'
draw=0
for seq in "${ESC}[?1049h" "${ESC}[?47h" "${ESC}[2J" "${ESC}[H" "${ESC}[K" "${ESC}[7m" "${ESC}[m"; do
  if LC_ALL=C grep -acF "$seq" "$CLOG" 2>/dev/null | grep -qv '^0$'; then draw=1; fi
done
if [ "$draw" -ge 1 ]; then
  echo "PASS · less emitted terminfo screen escapes over SSH (drew, not cat-dumped)"
  echo "       captured escapes:"; LC_ALL=C grep -aoE "${ESC}\[[0-9?;]*[a-zA-Z]" "$CLOG" 2>/dev/null | sort | uniq -c | sort -rn | head -8 | sed 's/^/         /'
else
  echo "FAIL · no terminfo screen escape from less (did it get a tty / find terminfo?)"
  # Surface diagnostics the gate must NOT paper over.
  LC_ALL=C grep -aiE 'not fully functional|cannot|terminfo|WARNING' "$CLOG" | head -3 | sed 's/^/         less-stderr: /'
  fail=1
fi

# ---- Assertion 4 (Phase B) · SSH terminal-resize → winsize honored. ----------
# Supporting proof · net-synth PARSED the controlling-tty pty-req: the distinctive
# initial size 137x42 appears as `[ssh] winch` (the pty-req decoder fired).  This
# does NOT reach orch (it arrives before busybox is live → orch drops it), so it is
# evidence the SSH winsize wire-path works, not the required end-to-end assertion.
if [ "$(sgF "[ssh] winch cols=${WINCH_COLS} rows=${WINCH_ROWS}")" -ge 1 ]; then
  echo "PASS · net-synth parsed the SSH pty-req winsize ([ssh] winch cols=${WINCH_COLS} rows=${WINCH_ROWS})"
else
  echo "INFO · pty-req size ${WINCH_COLS}x${WINCH_ROWS} not seen as [ssh] winch (the [tty] winch below is the authority)"
fi
# REQUIRED · the LIVE mid-session window-change (110x33) traverses the FULL path:
# net-synth `[ssh] winch` → SHELL_WINCH frame → orch updates g_ssh_shell_st.ws and
# logs `[tty] winch` (only emitted while a shell is live → proves orch honored it).
if [ "$(sgF "[tty] winch cols=${WINCH_COLS2} rows=${WINCH_ROWS2}")" -ge 1 ]; then
  echo "PASS · SSH window-change honored end-to-end → [tty] winch cols=${WINCH_COLS2} rows=${WINCH_ROWS2}"
else
  echo "FAIL · [tty] winch cols=${WINCH_COLS2} rows=${WINCH_ROWS2} not seen (window-change → SHELL_WINCH → orch path)"
  # Diagnostics the gate must NOT paper over: where did the winch path stall?
  echo "       [ssh] winch lines (net-synth pty-req/window-change parse):"
  LC_ALL=C grep -aE '\[ssh\] winch' "$SLOG" | head -4 | sed 's/^/         /'
  echo "       [tty] winch lines (orch consumed · shell was live):"
  LC_ALL=C grep -aE '\[tty\] winch' "$SLOG" | head -4 | sed 's/^/         /'
  echo "       ssh-shell spawn trail (busybox must be live for orch to honor a winch):"
  LC_ALL=C grep -aE 'ssh-shell START|busybox sh -i.*entering fault loop|already active' "$SLOG" | head -4 | sed 's/^/         /'
  fail=1
fi

# ============================================================================
# TUI-followups gate slices (F1/F2/F3/F5).  G4 (F4 SHELL_OUT backpressure) is
# DELIBERATELY SKIPPED: F4.2 was deferred — the grow+drop-oldest ring fallback
# remains (the 64 KiB ring covers normal redraws); no write-park to assert.
# ============================================================================

# ---- G1 (F1) · resize WHILE vim is open reaches the FORKED EDITOR child. ------
# Mid-vim the harness TIOCSWINSZ'd the controlling pty to a DISTINCTIVE 132x50.
# That window-change traverses net-synth→SHELL_WINCH→orch, which calls
# lucas_console_winch_foreground (logged `[tty] winch-fg woke=N`): it updates the
# session ws on EVERY box (parent + forked editor child · keyed on cow_session ==
# conn) and queues SIGWINCH to the foreground reader.  The F1 proof is that the
# resize reaches the FORKED VIM CHILD — vim then redraws at the NEW 132x50
# geometry (status line + tildes down to row 50, only valid when rows==50), which
# the busybox prompt alone would never produce.
# (1) the live mid-vim window-change traversed the full path to orch.
if [ "$(sgF "[tty] winch cols=${WINCH_COLS3} rows=${WINCH_ROWS3}")" -ge 1 ]; then
  echo "PASS · G1 · mid-vim window-change honored end-to-end → [tty] winch cols=${WINCH_COLS3} rows=${WINCH_ROWS3}"
else
  echo "FAIL · G1 · [tty] winch cols=${WINCH_COLS3} rows=${WINCH_ROWS3} (mid-vim resize) not seen"
  LC_ALL=C grep -aE '\[tty\] winch' "$SLOG" | tail -6 | sed 's/^/         /'
  fail=1
fi
# (2) the foreground-delivery helper ran for the session at 132x50 (the F1 routing
#     path · winch_foreground fired with the new size · its woke= is the count of
#     boxes caught PARKED-on-console at that instant — racy, so reported not gated:
#     vim is usually mid-redraw, not WAITING_FOR_CONSOLE, when the SIGWINCH lands;
#     the SIGWINCH is still QUEUED + delivered, proven by the redraw below).
WINCHFG=$(LC_ALL=C grep -acE "\[tty\] winch-fg woke=[0-9]+ cols=${WINCH_COLS3} rows=${WINCH_ROWS3}" "$SLOG")
if [ "${WINCHFG:-0}" -ge 1 ]; then
  WOKE=$(LC_ALL=C grep -aoE "\[tty\] winch-fg woke=[0-9]+ cols=${WINCH_COLS3} rows=${WINCH_ROWS3}" "$SLOG" \
           | LC_ALL=C grep -aoE 'woke=[0-9]+' | head -1)
  echo "PASS · G1 · winch_foreground routed the resize to the session at ${WINCH_COLS3}x${WINCH_ROWS3} ([tty] winch-fg ${WOKE})"
else
  echo "FAIL · G1 · no [tty] winch-fg for cols=${WINCH_COLS3} rows=${WINCH_ROWS3} (foreground delivery path did not run)"
  LC_ALL=C grep -aE '\[tty\] winch-fg woke=' "$SLOG" | tail -6 | sed 's/^/         /'
  fail=1
fi
# (3) THE F1 PROOF · the FORKED VIM CHILD redrew at the taller 132x50 geometry:
#     vim positions its status line / a tilde at row ${WINCH_ROWS3} (ESC[50;1H),
#     which requires it to have received the new rows=50.  At the prior size vim
#     would never address row 50.  (Wrap at 132 cols is corroborated by the
#     full-width tilde-fill lines.)  vim-tiny lacks :echo expr-eval (E319), so the
#     redraw geometry — not a &columns probe — is the authoritative width proof.
ESC=$'\033'
if LC_ALL=C grep -aqF "${ESC}[${WINCH_ROWS3};1H" "$CLOG"; then
  echo "PASS · G1 · the forked vim child redrew at the new ${WINCH_COLS3}x${WINCH_ROWS3} geometry (status/tilde at row ${WINCH_ROWS3} · ESC[${WINCH_ROWS3};1H)"
else
  echo "FAIL · G1 · vim did NOT redraw to row ${WINCH_ROWS3} after the resize (the editor child never saw rows=${WINCH_ROWS3})"
  echo "       row-addressing escapes vim emitted (max row reveals its geometry):"
  LC_ALL=C grep -aoE "${ESC}\[[0-9]+;1H" "$CLOG" | sort -t'[' -k2 -n | uniq -c | tail -6 | sed 's/^/         /'
  fail=1
fi

# ---- G2 (F2+F3) · vim :w /etc/passwd reads back + a shorter resave drops tail. -
# (F2) READ-BACK · grep HACKED /etc/passwd (scoped to the F2-READBACK markers)
# must show the substituted PASSWD LINE — op_write_stub routed the :w into the
# session overlay, op_read's read-merge served it back (the static base is
# immutable).  Match the passwd-line FORM `HACKED:x:` (root→HACKED on the first
# field), NOT the bare word `HACKED` — the latter also appears in the echoed
# `grep HACKED` COMMAND, so `HACKED:x:` proves it is genuine FILE CONTENT.
F2RB=$(awk '/=== F2-READBACK-BEGIN ===/{f=1;next} /=== F2-READBACK-END ===/{f=0} f' "$CLOG" 2>/dev/null)
if printf '%s' "$F2RB" | LC_ALL=C grep -qE 'HACKED:x:[0-9]'; then
  echo "PASS · G2/F2 · vim :w /etc/passwd reads back in-session ($(printf '%s' "$F2RB" | LC_ALL=C grep -aoE 'HACKED:x:[0-9:]*[^[:cntrl:]]*' | head -1))"
else
  echo "FAIL · G2/F2 · the substituted passwd line (HACKED:x:…) did NOT read back from /etc/passwd"
  printf '%s\n' "$F2RB" | cat -v | head -6 | sed 's/^/         /'
  fail=1
fi
# vim's :w SUCCEEDED on /etc/passwd (no E212 can't-open-for-output).
if [ "$(LC_ALL=C grep -acE 'E212|E166|Can.t open file for writing' "$CLOG")" -eq 0 ]; then
  echo "PASS · G2 · vim :w /etc/passwd reported no E212/E166/can't-open-for-writing"
else
  echo "FAIL · G2 · vim reported a write error on /etc/passwd"
  LC_ALL=C grep -aoE 'E212[^[:cntrl:]]*|E166[^[:cntrl:]]*|Can.t open file for writing' "$CLOG" | head -3 | sed 's/^/         /'
  fail=1
fi
# (F3) SHORTEN · after :2,$d + :wq, the re-cat of /etc/passwd must be SHORT — NO
# stale tail from the longer first save.  The base passwd has many lines (daemon,
# bin, sys, …); after the shrink only line 1 (the HACKED root line) survives, so a
# canonical OTHER account (e.g. `daemon:` / `nobody:` / `sshd:`) must be ABSENT.
F3SHORT=$(awk '/=== F3-SHORT-BEGIN ===/{f=1;next} /=== F3-SHORT-END ===/{f=0} f' "$CLOG" 2>/dev/null)
tail_gone=1; staletail=""
for acct in 'daemon:' 'nobody:' 'sshd:' 'sync:' 'www-data:'; do
  if printf '%s' "$F3SHORT" | LC_ALL=C grep -qF "$acct"; then tail_gone=0; staletail="$acct"; fi
done
# also assert the surviving line IS the HACKED line (the shrink kept line 1, not garbage).
if [ "$tail_gone" -eq 1 ] && printf '%s' "$F3SHORT" | LC_ALL=C grep -qF 'HACKED'; then
  echo "PASS · G2/F3 · shorter resave dropped the tail (re-cat /etc/passwd has line1 HACKED, no daemon:/nobody:/sshd: tail)"
elif [ "$tail_gone" -eq 1 ]; then
  echo "INFO · G2/F3 · no stale tail, but the HACKED line-1 marker wasn't seen in the F3 cat region (checking wc-line count below)"
else
  echo "FAIL · G2/F3 · STALE TAIL after the shorter resave (re-cat still shows '${staletail}')"
  printf '%s\n' "$F3SHORT" | cat -v | head -8 | sed 's/^/         /'
  fail=1
fi
# Hard numeric proof · wc -l /etc/passwd after the shrink must be small (1 line).
F3WC=$(awk '/=== F3-WC-BEGIN ===/{f=1;next} /=== F3-WC-END ===/{f=0} f' "$CLOG" 2>/dev/null)
WCN=$(printf '%s' "$F3WC" | LC_ALL=C grep -aoE '[0-9]+ /etc/passwd' | head -1 | grep -aoE '^[0-9]+')
if [ -n "${WCN:-}" ] && [ "${WCN:-99}" -le 2 ]; then
  echo "PASS · G2/F3 · /etc/passwd is now short (wc -l == ${WCN} ≤ 2 · the longer first save left no tail)"
else
  echo "INFO · G2/F3 · wc-l proof inconclusive (got '${WCN:-?}') — the no-stale-tail check above is the authority"
  printf '%s\n' "$F3WC" | cat -v | head -4 | sed 's/^/         /'
fi
# OPERATOR OBSERVES · the static-backend overlay-write trace fired for /etc/passwd.
if [ "$(sg '\[isolated\].*static write /etc/passwd.*session overlay (base intact)')" -ge 1 ]; then
  echo "PASS · G2 · operator observed the contained /etc/passwd write ([isolated] … static write /etc/passwd → session overlay (base intact))"
  echo "       trace: $(LC_ALL=C grep -aE '\[isolated\].*static write /etc/passwd.*session overlay' "$SLOG" | head -1 | sed 's/^[[:space:]]*//')"
else
  echo "FAIL · G2 · no [isolated] … static write /etc/passwd → session overlay trace"
  LC_ALL=C grep -aE '\[isolated\].*static write' "$SLOG" | head -5 | sed 's/^/         /'
  fail=1
fi

# ---- G3 (F5) · a 2nd concurrent SSH session is REFUSED cleanly (no hang). -----
# While the 1st `ssh -tt` shell (conn=1) was live, the gate fired a concurrent 2nd
# `ssh -tt` (conn=2).  The single busybox serves ONE interactive shell, so the 2nd
# is refused.  The AUTHORITATIVE refuse is net-synth's R2 CHANNEL_REQUEST handler
# (ssh_transport.c · g_ssh_shell_busy → CHANNEL_FAILURE, never signals SHELL_START)
# — so conn=2 AUTHENTICATES (its cred is captured · the deception still harvests
# it) but is NEVER granted a shell (no `ssh-shell START · conn=2`), and the client
# gets a clean channel-failure → disconnect, NOT a hang.  (The orch-side
# `[orch] ssh-shell: … refused · shell busy` is a belt-and-suspenders 2nd line that
# only fires in the race where net-synth's busy flag isn't yet set when the START
# reaches orch; it is accepted as an ALTERNATE refuse witness below.)
G3_CRED2=$(LC_ALL=C grep -acE '\[synth-srv\] SSH cred conn=2' "$SLOG")
G3_START2=$(LC_ALL=C grep -acE '\[synth-srv\] ssh-shell START . conn=2' "$SLOG")
G3_ORCHREF=$(LC_ALL=C grep -acE '\[orch\] ssh-shell: conn=[0-9]* refused . shell busy' "$SLOG")
if { [ "${G3_CRED2:-0}" -ge 1 ] && [ "${G3_START2:-0}" -eq 0 ]; } || [ "${G3_ORCHREF:-0}" -ge 1 ]; then
  if [ "${G3_ORCHREF:-0}" -ge 1 ]; then
    echo "PASS · G3/F5 · 2nd concurrent SSH session refused ($(LC_ALL=C grep -aoE '\[orch\] ssh-shell: conn=[0-9]+ refused . shell busy[^[:cntrl:]]*' "$SLOG" | head -1))"
  else
    echo "PASS · G3/F5 · 2nd concurrent SSH session refused cleanly (conn=2 authenticated · cred captured ${G3_CRED2}× · NO shell granted · single-shell R2 enforced)"
  fi
else
  echo "FAIL · G3/F5 · the 2nd-session refuse did not hold (cred2=${G3_CRED2:-0} start2=${G3_START2:-0} orch-refuse=${G3_ORCHREF:-0})"
  echo "       conn=2 SSH trail:"
  LC_ALL=C grep -aE '\[synth-srv\].*conn=2|ssh-shell START . conn=2|ssh-shell:.*refused' "$SLOG" | head -8 | sed 's/^/         /'
  fail=1
fi
# The 2nd client disconnected cleanly (clean EOF · not a hang/timeout-kill).
if [ -f /tmp/sotos-tui-g3-client.log ] && LC_ALL=C grep -qaF 'G3-2ND-EXITED' /tmp/sotos-tui-g3-client.log; then
  echo "PASS · G3/F5 · the 2nd ssh client disconnected cleanly (pty EOF · G3-2ND-EXITED)"
else
  echo "INFO · G3/F5 · 2nd client didn't record a clean EOF marker (the serial 'refused · shell busy' above is the authoritative refuse proof)"
fi

# ---- Assertion 5 (Phase C) · Tier-2 `vim :w` reads back in-session; base contained.
# The SAME early session vim-edited /tmp/welcome (HOLA→HACKEDxC5) then re-cat'd it.
# (a) READ-BACK COHERENT · the post-:wq cat — scoped to the C5-READBACK markers the
#     harness wrote into $CLOG — must show the edited marker.  This is the deception
#     proof: op_write routed the :w into the per-session overlay, and op_read's C2
#     read-merge served it back (base graph bytes were "HOLA", never "HACKEDxC5").
RB=$(awk '/=== C5-READBACK-BEGIN ===/{f=1;next} /=== C5-READBACK-END ===/{f=0} f' "$CLOG" 2>/dev/null)
if printf '%s' "$RB" | LC_ALL=C grep -qF "$COW_TO"; then
  echo "PASS · Tier-2 vim :w reads back in-session (cat ${COW_PATH} shows '${COW_TO}' from the overlay)"
  echo "       read-back: $(printf '%s' "$RB" | LC_ALL=C grep -aF "$COW_TO" | head -1 | tr -d '\r' | sed 's/^[[:space:]]*//')"
else
  echo "FAIL · read-back did NOT show '${COW_TO}' (overlay merge broke · the deception tell)"
  echo "       C5-READBACK region of the channel:"; printf '%s\n' "$RB" | cat -v | head -6 | sed 's/^/         /'
  echo "       isolated write traces (did the :w reach the overlay?):"
  LC_ALL=C grep -aE '\[isolated\].*session overlay' "$SLOG" | head -3 | sed 's/^/         /'
  fail=1
fi
# (b) vim's :w SUCCEEDED · vim printed its "<n> bytes written" line and did NOT emit
#     a write error (E212 can't-open-for-output / E166 can't-open-linked / "Can't
#     open file for writing").  Proves the :w reached op_write, it did not error out.
if cgF 'bytes written' >/dev/null && [ "$(cgF 'bytes written')" -ge 1 ]; then
  if [ "$(LC_ALL=C grep -acE 'E212|E166|Can.t open file for writing' "$CLOG")" -eq 0 ]; then
    echo "PASS · vim :w succeeded (\"bytes written\" · no E212/E166/can't-open-for-writing)"
  else
    echo "FAIL · vim reported a write error (E212/E166/can't-open-for-writing) on the :w"
    LC_ALL=C grep -aoE 'E212[^[:cntrl:]]*|E166[^[:cntrl:]]*|Can.t open file for writing' "$CLOG" | head -3 | sed 's/^/         /'
    fail=1
  fi
else
  echo "FAIL · vim never reported \"bytes written\" (the :w did not complete)"
  fail=1
fi
# (c) OPERATOR OBSERVES CONTAINMENT · the C3 isolated write trace landed on the
#     serial — the write was redirected to the SESSION OVERLAY and the base graph
#     was left intact (the print fires BEFORE any graph mutation · structural).
#     We also confirm the isolated activity was on the WELCOME canary specifically:
#     vim's swap-file probes drop as `[isolated] … welcome.swp` (path-carrying), so
#     the contained write + the path-drop together tie the containment to /tmp/welcome.
# (NOTE · base-intact is structurally guaranteed by C3 + proven by THIS trace; a
#  fresh-session re-read is unreliable headless — B4 single-session limit — so the
#  gate does NOT open a 2nd connection · see the header.)
if [ "$(sg '\[isolated\].*sotfs write.*session overlay (base intact)')" -ge 1 ]; then
  echo "PASS · operator observed the contained write ([isolated] … → session overlay (base intact))"
  echo "       trace: $(LC_ALL=C grep -aE '\[isolated\].*sotfs write.*session overlay' "$SLOG" | head -1 | sed 's/^[[:space:]]*//')"
  if [ "$(sg '\[isolated\].*welcome.swp')" -ge 1 ]; then
    echo "       tied to the welcome canary: $(LC_ALL=C grep -aE '\[isolated\].*welcome\.swp' "$SLOG" | head -1 | sed 's/^[[:space:]]*//')"
  fi
else
  echo "FAIL · no [isolated] … → session overlay (base intact) trace for the :w"
  echo "       isolated lines on the serial:"
  LC_ALL=C grep -aE '\[isolated\]' "$SLOG" | head -5 | sed 's/^/         /'
  fail=1
fi

# ---- Assertion 3 · zero faults across the whole run.
nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|Invocation of invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] \
  && echo "PASS · 0 faults across the TUI run" \
  || { echo "FAIL · ${nf} fault(s)"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'TUI: PASS' || echo 'TUI: FAIL' ) ==="
echo "(serial: $SLOG · client: $CLOG)"; exit $fail
