# Live capture figures

Side-by-side **attacker vs operator** terminal panes for the two deception scenarios
documented in the root [README](../../README.md#live-captures).

| File | Scenario | What it shows |
|------|----------|---------------|
| `scenario-A-inhost.svg` | In-host payload | Malware stdout (what the attacker *believes*) vs serial log (tier promotion, curvature alert, synthetic fork). |
| `scenario-B-recon.svg` | External recon | nmap / TLS / SSH session (credible prod host) vs `sottrace` + credential harvest + canary trip + write containment. |

The committed SVGs are **representative** of real serial/`sottrace` output validated by
the gate battery (`tools/*-gate.sh`, `scripts/labyrinth-validate.sh`). Text is
verbatim-style from documented runs, not hand-wavy mockups.

## Regenerate (representative)

```bash
python3 tools/captures/make_figures.py
```

Writes both SVGs into this directory.

## Regenerate from a live boot

```bash
just build && just run-headless   # or your usual boot recipe
tools/captures/capture.sh         # tmux panes + optional asciinema
# — or the focused grab scripts:
tools/captures/grab-inhost.sh     # Scenario A serial log → build/capture-inhost-serial.log
tools/captures/grab-recon.sh      # Scenario B SSH/TLS → build/capture-recon-*.log
python3 tools/captures/make_figure_A_real.py   # → scenario-A-inhost-REAL.svg
python3 tools/captures/make_figure_B_real.py   # → scenario-B-recon-REAL.svg
```

Convert SVG → PNG for slide decks: `rsvg-convert -o out.png in.svg` or any browser export.
