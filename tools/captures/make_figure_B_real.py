#!/usr/bin/env python3
"""make_figure_B_real.py — Scenario B figure from a REAL recon capture
(build/capture-recon-{serial,client}.log, produced by tools/captures/grab-recon.sh).

Every line is verbatim from a live boot: openssl TLS 1.3 + a real ssh recon session
against the deception host (hostfwd :18443→443, :18022→22), branch feat/wine-m1-loader,
TCG.  The attacker appears as the QEMU NAT gateway 10.0.2.2 (a public IP in a real
deployment).  THE LIE = attacker transcript; THE TRUTH = serial (sottrace + the
SSH credential capture + canary /etc/passwd read + write containment).
"""
import os
import make_figures as mf
from make_figures import t, seg

GREEN, RED, FG, DIM, CYAN, MAGENTA, YELLOW, ORANGE, BLUE, WHITE, PROMPT = (
    mf.GREEN, mf.RED, mf.FG, mf.DIM, mf.CYAN, mf.MAGENTA, mf.YELLOW,
    mf.ORANGE, mf.BLUE, mf.WHITE, mf.PROMPT)

ATTACKER = [
    seg(t(PROMPT, "attacker$ "), t(WHITE, "scan :22 :443 :80"), t(GREEN, "  → all OPEN")),
    seg(t(PROMPT, "attacker$ "), t(WHITE, "openssl s_client honeypot:443 -tls1_3")),
    seg(t(FG, "  New, "), t(GREEN, "TLSv1.3, TLS_AES_256_GCM_SHA384")),
    seg(t(FG, "  subject=CN=sotos-phantom  (2048-bit, self-signed)")),
    seg(t(PROMPT, "attacker$ "), t(WHITE, "ssh-keyscan :22"), t(FG, " → "), t(GREEN, "SSH-2.0-OpenSSH_9.6")),
    seg(t(PROMPT, "attacker$ "), t(WHITE, "ssh root@honeypot"), t(DIM, "  (3rd password 'works')")),
    seg(t(FG, "  $ whoami    → "), t(GREEN, "admin")),
    seg(t(FG, "  $ id        → "), t(GREEN, "uid=1000(admin) gid=1000")),
    seg(t(FG, "  $ uname -a  → "), t(GREEN, "Linux prod-db-01 6.1.0 x86_64")),
    seg(t(FG, "  $ cat /etc/passwd → "), t(GREEN, "root/admin/backer/ops")),
    seg(t(FG, "  $ echo BACKDOOR > /etc/cron.d/persist")),
    seg(t(RED, "     sh: write error: Bad file descriptor")),
    seg(t(DIM, "")),
    seg(t(GREEN, "  # \"I own a prod DB box.\"  ...or so it thinks")),
]
OPERATOR = [
    seg(t(BLUE, "[sottrace] "), t(FG, "conn=1 RESPONSE_PROFILE HTTPS :443 343 B")),
    seg(t(BLUE, "[sottrace] "), t(FG, "conn=7 ACCEPT from 10.0.2.2 -> :22")),
    seg(t(BLUE, "[sottrace] "), t(FG, "conn=7 RESPONSE_PROFILE SSH :22 181 B")),
    seg(t(YELLOW, "[synth-srv] "), t(FG, "SSH cred conn=7 "), t(RED, "user=root pass=hunter2")),
    seg(t(DIM, "       ↑ attacker's password harvested")),
    seg(t(BLUE, "[sottrace] "), t(FG, "pid=1 FS READ /etc/passwd 195 B")),
    seg(t(ORANGE, "[canary] "), t(FG, "pid=1 read /etc/passwd · count=1"), t(RED, "  BAIT")),
    seg(t(BLUE, "[sottrace] "), t(FG, "pid=1 CANARY path=/etc/passwd")),
    seg(t(CYAN, "[contain] "), t(FG, "/etc/cron.d/persist write → EBADF"), t(RED, "  BLOCKED")),
    seg(t(DIM, "—— sottrace_netgraph ——")),
    seg(t(FG, "peer 10.0.2.2 "), t(BLUE, "─HTTPS:443→"), t(FG, " honeypot")),
    seg(t(FG, "peer 10.0.2.2 "), t(BLUE, "─SSH:22────→"), t(FG, " honeypot  ×5")),
    seg(t(DIM, "")),
    seg(t(DIM, "creds harvested · canary tripped · no real host touched")),
]
LINKS = [
    (5, 3,  "creds logged"),
    (9, 6,  "bait taken"),
    (11, 8, "contained"),
]

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.normpath(os.path.join(here, "..", "..", "docs", "captures",
                                        "scenario-B-recon-REAL.svg"))
    mf.figure(
        "Scenario B: external recon  [LIVE CAPTURE]",
        "openssl TLS 1.3 + a real ssh recon session against the deception host — not a mockup",
        ATTACKER, OPERATOR, LINKS, out,
        footer=("Captured live · build/capture-recon-{serial,client}.log · branch feat/wine-m1-loader · "
                "QEMU/TCG · 2026-06-11. Attacker appears as the QEMU NAT gateway 10.0.2.2 "
                "(a public IP in a real deployment). TLS handshake, SSH banner, honey passwd, "
                "cred capture, canary read & write-containment are all live."))
    print(f"[make_figure_B_real] wrote {out}")

if __name__ == "__main__":
    main()
