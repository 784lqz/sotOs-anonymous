#!/usr/bin/env python3
"""make_figures.py — render the attacker-vs-operator "asymmetric truth" comparison
figures for sotOs, as slide-ready SVG (scalable; convert to PNG with rsvg-convert,
inkscape, or any browser "save as image").

Two scenarios, each a side-by-side pair of styled terminal panes:
  A · in-host payload   — attacker = malware stdout (what it BELIEVES)
                          operator = serial log (GROUND TRUTH: honey/ghost/phantom)
  B · external recon    — attacker = nmap/openssl/ssh (sees a "real" host)
                          operator = sottrace forensic trace (every byte recorded;
                                      the attacker's own C2 beacon flagged RED)

The text is VERBATIM-REPRESENTATIVE of real output documented in:
  docs/demo-agent-deception-runbook.md   (scenario A · the 5/6-stage walk-through)
  tools/tls13-gate.sh, tools/ja3s-ems-gate.sh, tools/ssh-*-gate.sh,
  docs/star-net-deception-complete.md, tools/sottrace_netgraph.py (scenario B)

Stdlib only.  Edit the LINE LISTS below to match a fresh real capture, then rerun.
"""
import html
import os

# ── geometry / palette ──────────────────────────────────────────────────────
FS      = 13          # font-size px
LH      = 19          # line-height px
CW      = 7.82        # monospace char width @ FS=13
PAD     = 14          # inner pane padding
CHROME  = 30          # window title-bar height
GUTTER  = 116         # center "truth-gap" gutter width
MARGIN  = 26
TITLE_H = 64
FOOT_H  = 34
FONT    = "Consolas, 'DejaVu Sans Mono', 'Courier New', monospace"

BG       = "#0b0e14"   # page background
PANE_BG  = "#11141c"   # terminal background
PANE_BG2 = "#0e1622"   # operator pane (slightly different tint)
BAR      = "#1c2230"   # title bar
FG       = "#c9d1d9"   # default text
DIM      = "#6b7689"   # muted/comment text
GREEN    = "#3fb950"   # malware "success" (the lie)
RED      = "#f85149"   # danger / C2 / refutation
CYAN     = "#39c5cf"   # [sentinel-ext]
MAGENTA  = "#d2a8ff"   # [functor]
YELLOW   = "#e3b341"   # [ghost]
ORANGE   = "#ff8a4b"   # [phantom]/[net-phantom]
BLUE     = "#6cb6ff"   # [dns]/[sottrace]
WHITE    = "#e6edf3"
PROMPT   = "#7ee787"

# a "line" is a list of (color, text) segments.
def seg(*pairs):
    return list(pairs)

def t(color, text):
    return (color, text)

# ── SCENARIO A · in-host payload (agent_deception.py) ─────────────────────────
# LEFT — attacker: malware stdout (what it believes happened)
A_ATTACKER = [
    seg(t(PROMPT, "honeypot$ "), t(WHITE, "python /honey-scripts/agent_deception.py")),
    seg(t(DIM, "")),
    seg(t(GREEN, "[+] Stage 1 "), t(FG, "Discovery & anti-analysis")),
    seg(t(FG, "[*]   PID 0xab23ef91   mem-map harvested 8421 B")),
    seg(t(GREEN, "[+] Stage 2 "), t(FG, "Credential harvest")),
    seg(t(RED, "[!]   exfiltrated "), t(FG, "/tmp/honey-aws-creds:")),
    seg(t(FG, "        aws_access_key_id = AKIA1234567890DEAD...")),
    seg(t(GREEN, "[+] Stage 3 "), t(FG, "Ransomware-style writes")),
    seg(t(FG, "[*]   'Encrypted' /tmp/doc_1.enc .. doc_7.enc")),
    seg(t(GREEN, "[+] Stage 4 "), t(FG, "Exfiltration to C2")),
    seg(t(RED, "[!]   C2 acknowledged: "), t(FG, "HTTP/1.1 200 OK")),
    seg(t(FG, "        Server: nginx/1.18")),
    seg(t(GREEN, "[+] Stage 5 "), t(FG, "DNS honey probe")),
    seg(t(RED, "[!]   Resolved "), t(FG, "malicious-c2.example -> 10.0.2.15")),
    seg(t(GREEN, "[+] Stage 6 "), t(FG, "Lateral fork (persistence)")),
    seg(t(FG, "[*]   forked child pid=9 ; waitpid -> 0 (alive)")),
    seg(t(DIM, "")),
    seg(t(GREEN, "[+] === 6/6 stages exercised · SUCCESS ===")),
]
# RIGHT — operator: serial ground truth
A_OPERATOR = [
    seg(t(BLUE, "[orch] "), t(FG, "spawn python  display_pid=0xab23ef91"), t(DIM, "  (OBSD-ζ)")),
    seg(t(DIM, "       heap base jittered +187 MiB")),
    seg(t(CYAN, "[sentinel-ext] "), t(FG, "HONEY_READ /tmp/honey-aws-creds"), t(RED, "  PHANTOM")),
    seg(t(CYAN, "[sentinel-ext] "), t(FG, "HONEY_READ /tmp/honey-readme.txt"), t(RED, "  PHANTOM")),
    seg(t(DIM, "       AKIA..DEAD is a sentinel string · marks exfil")),
    seg(t(CYAN, "[sentinel-ext] "), t(FG, "WRITE count=50 → promote Tier-1")),
    seg(t(MAGENTA, "[functor] "), t(FG, "pid=1  F_0 → F_1  (ghost mode)")),
    seg(t(YELLOW, "[ghost] "), t(FG, "write(fd≥3) SILENT · rollback ×7"), t(RED, "  DISK INTACT")),
    seg(t(CYAN, "[sentinel-ext] "), t(FG, "TCP_OPEN 45.77.12.98:443 → Tier-2")),
    seg(t(MAGENTA, "[functor] "), t(FG, "pid=1  F_1 → F_2")),
    seg(t(ORANGE, "[phantom] "), t(FG, "redirect 45.77.12.98:443 ·"), t(RED, " NO SYN SENT")),
    seg(t(ORANGE, "[net-phantom] "), t(FG, "FAKE_C2 queued '200 OK'"), t(DIM, "  synthetic")),
    seg(t(BLUE, "[dns] "), t(FG, "HIT malicious-c2.example → 10.0.2.15"), t(RED, "  PHANTOM")),
    seg(t(BLUE, "[procd] "), t(FG, "PHANTOM_FORK slot=9 ·"), t(RED, " NO REAL TCB")),
    seg(t(DIM, "—— postmortem ——")),
    seg(t(PROMPT, "sotos> "), t(WHITE, "sotinfo")),
    seg(t(FG, "  pid=0xab23ef91 "), t(RED, "TIER2"), t(FG, " · 2 honey · redirects=1")),
    seg(t(PROMPT, "sotos> "), t(WHITE, "tpm-pcrs"), t(DIM, "   PCR-8/9/10 UNCHANGED")),
]
# truth-gap connectors: (left_line_idx, right_line_idx, label)
A_LINKS = [
    (5, 2,  "phantom creds"),
    (8, 7,  "rolled back"),
    (10, 10, "never sent"),
    (13, 12, "hijacked"),
    (15, 13, "no TCB"),
]

# ── SCENARIO B · external recon ───────────────────────────────────────────────
B_ATTACKER = [
    seg(t(PROMPT, "attacker$ "), t(WHITE, "nmap -sV honeypot")),
    seg(t(FG, "22/tcp  open  ssh      "), t(GREEN, "OpenSSH 9.6 (proto 2.0)")),
    seg(t(FG, "443/tcp open  ssl/http "), t(GREEN, "nginx 1.18.0")),
    seg(t(DIM, "")),
    seg(t(PROMPT, "attacker$ "), t(WHITE, "openssl s_client -connect honeypot:443 -tls1_3")),
    seg(t(FG, "  Protocol : "), t(GREEN, "TLSv1.3")),
    seg(t(FG, "  Cipher   : "), t(GREEN, "TLS_AES_256_GCM_SHA384")),
    seg(t(FG, "  Peer cert: CN=honeypot  (TLS handshake OK)")),
    seg(t(DIM, "  JA3S/JA4S byte-identical to stock nginx")),
    seg(t(DIM, "")),
    seg(t(PROMPT, "attacker$ "), t(WHITE, "ssh admin@honeypot -v")),
    seg(t(FG, "  kex: "), t(GREEN, "curve25519-sha256"), t(FG, "  cipher: aes128-ctr")),
    seg(t(FG, "  mac: hmac-sha2-256   host key "), t(GREEN, "validated")),
    seg(t(FG, "  admin@honeypot's password: "), t(WHITE, "█")),
    seg(t(DIM, "")),
    seg(t(GREEN, "  # looks, smells, fingerprints like a real box")),
]
B_OPERATOR = [
    seg(t(BLUE, "[sottrace] "), t(FG, "conn=7 ACCEPT 203.0.113.9:51344 -> :443")),
    seg(t(BLUE, "[sottrace] "), t(FG, "conn=7 RESPONSE_PROFILE TLS13 :443 4096 B")),
    seg(t(CYAN, "[ja3s] "), t(FG, "inbound :443 md5="), t(WHITE, "1af33e16..302c")),
    seg(t(DIM, "       == nginx · byte-exact, served by sotOs")),
    seg(t(BLUE, "[sottrace] "), t(FG, "conn=8 ACCEPT 203.0.113.9:51902 -> :22")),
    seg(t(BLUE, "[sottrace] "), t(FG, "conn=8 RESPONSE_PROFILE SSH :22 1144 B")),
    seg(t(DIM, "       SSH persona · real KEX, synthetic host")),
    seg(t(BLUE, "[sottrace] "), t(FG, "NET CONNECT 45.77.12.98:443 conn=9")),
    seg(t(RED, "       ⤴ non-RFC1918 · flagged likely-C2")),
    seg(t(DIM, "—— sottrace_netgraph.py ——")),
    seg(t(FG, "peer 203.0.113.9 "), t(BLUE, "─TLS :443→"), t(FG, " honeypot")),
    seg(t(FG, "peer 203.0.113.9 "), t(BLUE, "─SSH :22 →"), t(FG, " honeypot")),
    seg(t(FG, "p1 "), t(RED, "─CONNECT→ peer 45.77.12.98:443")),
    seg(t(RED, "                    [ RED · likely C2 ]")),
    seg(t(DIM, "")),
    seg(t(DIM, "every byte the attacker saw is recorded;")),
    seg(t(DIM, "its own beacon is the only thing that left.")),
]
B_LINKS = [
    (2, 1,  "nginx-exact"),
    (5, 5,  "synthetic"),
    (12, 7, "beacon seen"),
]


# ── SVG rendering ─────────────────────────────────────────────────────────────
def esc(s):
    return html.escape(s, quote=True)

def line_len(line):
    return sum(len(x[1]) for x in line)

def render_pane(x, y, w, h, title, title_color, lines, pane_bg):
    out = []
    # body
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" fill="{pane_bg}" '
               f'stroke="#2a3242" stroke-width="1"/>')
    # title bar
    out.append(f'<path d="M{x},{y+7} a7,7 0 0 1 7,-7 h{w-14} a7,7 0 0 1 7,7 v{CHROME-7} h{-w} z" '
               f'fill="{BAR}"/>')
    for i, c in enumerate(("#f85149", "#e3b341", "#3fb950")):
        out.append(f'<circle cx="{x+16+i*16}" cy="{y+CHROME/2}" r="5" fill="{c}"/>')
    out.append(f'<text x="{x+64}" y="{y+CHROME/2+4}" font-family="{FONT}" font-size="11" '
               f'fill="{title_color}" font-weight="bold">{esc(title)}</text>')
    # lines
    ty0 = y + CHROME + PAD + FS
    for li, line in enumerate(lines):
        ty = ty0 + li * LH
        tx = x + PAD
        parts = [f'<text x="{tx}" y="{ty}" font-family="{FONT}" font-size="{FS}" xml:space="preserve">']
        for color, text in line:
            if text == "":
                continue
            parts.append(f'<tspan fill="{color}">{esc(text)}</tspan>')
        parts.append('</text>')
        out.append("".join(parts))
    return "\n".join(out)

def figure(scenario_id, subtitle, attacker, operator, links, outfile, footer=None):
    # size from content
    la = max((line_len(l) for l in attacker), default=40)
    lo = max((line_len(l) for l in operator), default=40)
    paneA_w = int(la * CW + 2 * PAD) + 6
    paneB_w = int(lo * CW + 2 * PAD) + 6
    rows = max(len(attacker), len(operator))
    pane_h = CHROME + 2 * PAD + rows * LH
    W = MARGIN + paneA_w + GUTTER + paneB_w + MARGIN
    H = TITLE_H + pane_h + FOOT_H + MARGIN
    xA = MARGIN
    xB = MARGIN + paneA_w + GUTTER
    yP = TITLE_H

    s = []
    s.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
             f'viewBox="0 0 {W} {H}" font-family="{FONT}">')
    s.append(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
    # header
    s.append(f'<text x="{MARGIN}" y="30" font-family="{FONT}" font-size="17" fill="{WHITE}" '
             f'font-weight="bold">sotOs · Asymmetric Truth — {esc(scenario_id)}</text>')
    s.append(f'<text x="{MARGIN}" y="50" font-family="{FONT}" font-size="12" fill="{DIM}">'
             f'{esc(subtitle)}</text>')
    # panes
    s.append(render_pane(xA, yP, paneA_w, pane_h, "ATTACKER VIEW  —  what the adversary believes",
                         GREEN, attacker, PANE_BG))
    s.append(render_pane(xB, yP, paneB_w, pane_h, "OPERATOR VIEW  —  ground truth (serial / sottrace)",
                         CYAN, operator, PANE_BG2))
    # truth-gap gutter label
    cx = xA + paneA_w + GUTTER / 2
    s.append(f'<text x="{cx}" y="{yP-8}" font-family="{FONT}" font-size="11" fill="{RED}" '
             f'text-anchor="middle" font-weight="bold">TRUTH GAP</text>')
    # connectors
    ty0A = yP + CHROME + PAD + FS
    for (lidx, ridx, label) in links:
        y1 = ty0A + lidx * LH - FS / 2 + 3
        y2 = ty0A + ridx * LH - FS / 2 + 3
        x1 = xA + paneA_w
        x2 = xB
        midx = (x1 + x2) / 2
        s.append(f'<path d="M{x1},{y1} C{midx},{y1} {midx},{y2} {x2},{y2}" '
                 f'fill="none" stroke="{RED}" stroke-width="1.3" stroke-dasharray="4 3" opacity="0.8"/>')
        s.append(f'<circle cx="{x1}" cy="{y1}" r="2.6" fill="{GREEN}"/>')
        s.append(f'<circle cx="{x2}" cy="{y2}" r="2.6" fill="{RED}"/>')
        s.append(f'<text x="{midx}" y="{(y1+y2)/2-3}" font-family="{FONT}" font-size="9.5" '
                 f'fill="{RED}" text-anchor="middle">{esc(label)}</text>')
    # footer
    fy = yP + pane_h + 22
    foot = footer or ("Representative of real serial/sottrace output (see docs/captures/README.md). "
                      "Regenerate live: tools/captures/capture.sh")
    s.append(f'<text x="{MARGIN}" y="{fy}" font-family="{FONT}" font-size="10.5" fill="{DIM}">'
             f'{esc(foot)}</text>')
    s.append('</svg>')
    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(s))
    print(f"[make_figures] wrote {outfile}  ({W}x{H})")

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = os.path.normpath(os.path.join(here, "..", "..", "docs", "captures"))
    os.makedirs(outdir, exist_ok=True)
    figure("Scenario A: in-host payload",
           "agent_deception.py runs UNMODIFIED · every '[+] SUCCESS' is a lie about the world below",
           A_ATTACKER, A_OPERATOR, A_LINKS,
           os.path.join(outdir, "scenario-A-inhost.svg"))
    figure("Scenario B: external recon",
           "nmap / openssl / ssh against the deception host · a 'real' box on the wire, fully recorded underneath",
           B_ATTACKER, B_OPERATOR, B_LINKS,
           os.path.join(outdir, "scenario-B-recon.svg"))

if __name__ == "__main__":
    main()
