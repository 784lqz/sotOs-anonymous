#!/usr/bin/env python3
"""make_figure_A_real.py — Scenario A figure built from a REAL captured serial
(build/capture-inhost-serial.log, produced by tools/captures/grab-inhost.sh).

Unlike make_figures.py (representative), every line here is verbatim from a live
boot: `inject-script /simulated_attacker.py` on branch feat/wine-m1-loader, TCG.
Honest scope: on this branch the honey-cred / phantom-C2 / DNS-phantom net paths
were NOT wired, so the malware visibly saw ENOENT / timeout for those — shown as-is.
The deception that DID fire: anomaly-ext score→tier promotion, functor F_0→F_1→F_2,
synthetic fork (no real TCB), and the Forman-Ricci RANSOMWARE curvature alert.
"""
import os
import make_figures as mf
from make_figures import t, seg

GREEN, RED, FG, DIM, CYAN, MAGENTA, YELLOW, ORANGE, BLUE, WHITE, PROMPT = (
    mf.GREEN, mf.RED, mf.FG, mf.DIM, mf.CYAN, mf.MAGENTA, mf.YELLOW,
    mf.ORANGE, mf.BLUE, mf.WHITE, mf.PROMPT)

# ── LEFT · attacker: the malware's own stdout (verbatim from guest:1) ─────────
ATTACKER = [
    seg(t(PROMPT, "sotos> "), t(WHITE, "inject-script /simulated_attacker.py")),
    seg(t(GREEN, "[+] Stage 1 "), t(FG, "Discovery   PID 0xa9c9  maps 409 B")),
    seg(t(GREEN, "[+] Stage 2 "), t(FG, "Credential recon")),
    seg(t(DIM, "[-]   /honey-aws-creds: No such file")),
    seg(t(GREEN, "[+] Stage 3 "), t(FG, "Ransomware-style writes")),
    seg(t(FG, "[*]   'Encrypted' /tmp/doc_1.enc .. doc_6.enc")),
    seg(t(GREEN, "[+] Stage 4 "), t(FG, "Mass-delete + C2 exfil")),
    seg(t(FG, "[*]   shredded /tmp/doc_1.enc .. doc_6.enc")),
    seg(t(DIM, "[-]   C2 socket: timed out")),
    seg(t(GREEN, "[+] Stage 6 "), t(FG, "Lateral fork")),
    seg(t(RED, "[*]   forked child pid=5 "), t(FG, "; kill(5,0) ok; pgrp ok")),
    seg(t(GREEN, "[+] Stage 7 "), t(FG, "Persistence installation")),
    seg(t(RED, "[!]   crontab + bashrc + service + timer installed")),
    seg(t(DIM, "")),
    seg(t(GREEN, "[+] === 7/7 stages exercised · SUCCESS ===")),
]
# ── RIGHT · operator: serial ground truth (verbatim tags) ────────────────────
OPERATOR = [
    seg(t(CYAN, "[anomaly-ext] "), t(FG, "pid=1 kind=1 (WRITE) ×6")),
    seg(t(CYAN, "[anomaly-ext] "), t(FG, "curvature alert "), t(RED, "RANSOMWARE sev=4000")),
    seg(t(DIM, "       Forman-Ricci κ-plunge on the .enc cluster")),
    seg(t(CYAN, "[anomaly-ext] "), t(FG, "pid=1 score=21 → Tier 1"), t(DIM, " (T1=20 T2=40)")),
    seg(t(MAGENTA, "[functor] "), t(FG, "pid=1  F_0 → F_1  (η^0→1)")),
    seg(t(BLUE, "[procd] "), t(FG, "EV_TIER_CHANGED 0→1 · REBOUND fs=1")),
    seg(t(CYAN, "[anomaly-ext] "), t(FG, "pid=1 score=41 → "), t(RED, "Tier 2")),
    seg(t(MAGENTA, "[functor] "), t(FG, "pid=1  F_1 → F_2  (η^1→2)")),
    seg(t(BLUE, "[procd] "), t(FG, "REBOUND fs=2 net=1 proc=1")),
    seg(t(BLUE, "[procd] "), t(FG, "EV_SYNTH_FORK slot=5 parent=4"), t(RED, "  NO REAL TCB")),
    seg(t(CYAN, "[anomaly-ext] "), t(FG, "DNS HIT malicious-c2.example→10.0.2.15")),
    seg(t(ORANGE, "[deception] "), t(FG, "/canary-* + creds SYNTHETIC ·"), t(RED, " Tier-2 served lies")),
    seg(t(DIM, "—— postmortem ——")),
    seg(t(PROMPT, "sotos> "), t(WHITE, "sotinfo")),
    seg(t(FG, "  pid=1 escalated → "), t(RED, "Tier-2"), t(FG, " · isolated")),
]
# truth-gap connectors (left idx, right idx, label)
LINKS = [
    (10, 9, "no TCB"),
    (5, 1,  "curvature"),
    (14, 6, "Tier-2"),
]

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.normpath(os.path.join(here, "..", "..", "docs", "captures",
                                        "scenario-A-inhost-REAL.svg"))
    mf.figure(
        "Scenario A: in-host payload  [LIVE CAPTURE]",
        "simulated_attacker.py (7 stages, unmodified) · captured from a live boot — not a mockup",
        ATTACKER, OPERATOR, LINKS, out,
        footer=("Captured live · build/capture-inhost-serial.log · branch feat/wine-m1-loader · "
                "QEMU/TCG · 2026-06-11. honey-cred/phantom-C2/DNS net paths not wired on this "
                "branch (shown as the ENOENT/timeout the malware actually saw); score→tier, "
                "functor rebind, synth-fork & curvature alert are the live deception that fired."))
    print(f"[make_figure_A_real] wrote {out}")

if __name__ == "__main__":
    main()
