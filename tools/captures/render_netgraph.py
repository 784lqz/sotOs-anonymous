#!/usr/bin/env python3
"""render_netgraph.py — render a sottrace.netgraph.dot (produced by the REAL tool
tools/sottrace_netgraph.py) into a slide-ready SVG, in the sotOs capture style.

The .dot is the authentic operator artifact; this is just a viewer that matches the
look of the other capture figures (so it can sit next to them on a slide).  Graphviz
is NOT required.  Layout is the natural left→right honeypot flow:

    inbound peers ─▶ honeypot ─▶ resident procs ─▶ egress peers (C2)

Usage: render_netgraph.py [in.dot] [out.svg]   (defaults: docs/captures/*)
Stdlib only.
"""
import html
import os
import re
import sys

FONT = "Consolas, 'DejaVu Sans Mono', 'Courier New', monospace"
BG    = "#0b0e14"
FG    = "#c9d1d9"
DIM   = "#6b7689"
RED   = "#f85149"
GREY  = "#8b949e"
BLUE  = "#6cb6ff"
WHITE = "#e6edf3"
EDGE  = "#39414f"
NODE_BG = "#11141c"

def esc(s):
    return html.escape(s, quote=True)

def parse_dot(path):
    nodes = {}   # id -> {label, shape, fill}
    edges = []   # (src, dst, label)
    edge_re = re.compile(r'"([^"]+)"\s*->\s*"([^"]+)"\s*\[label="([^"]*)"\]')
    node_re = re.compile(r'^\s*"([^"]+)"\s*\[([^\]]*)\]')
    with open(path, encoding="utf-8") as f:
        for line in f:
            if "->" in line:                       # edge line — never a node def
                m = edge_re.search(line)
                if m:
                    edges.append((m.group(1), m.group(2), m.group(3)))
                continue
            m = node_re.search(line)               # node def line
            if not m:
                continue
            nid, attrs = m.group(1), m.group(2)
            lab = re.search(r'label="([^"]*)"', attrs)
            shp = re.search(r'shape=(\w+)', attrs)
            fil = re.search(r'fillcolor=(\w+)', attrs)
            nodes[nid] = {
                "label": lab.group(1) if lab else nid,
                "shape": shp.group(1) if shp else "ellipse",
                "fill":  fil.group(1) if fil else None,
            }
    return nodes, edges

def columnize(edges):
    """Assign each node to a column 0..3 by role derived from the edges."""
    inbound, procs, egress_peers = set(), set(), set()
    for src, dst, _ in edges:
        if dst == "honeypot":
            inbound.add(src)
        elif src.startswith("p") and dst.startswith("peer:"):
            procs.add(src)
            egress_peers.add(dst)
    cols = {0: sorted(inbound), 1: ["honeypot"], 2: sorted(procs), 3: sorted(egress_peers)}
    return cols

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    cap  = os.path.normpath(os.path.join(here, "..", "..", "docs", "captures"))
    dot  = sys.argv[1] if len(sys.argv) > 1 else os.path.join(cap, "sottrace.netgraph.dot")
    out  = sys.argv[2] if len(sys.argv) > 2 else os.path.join(cap, "sottrace-netgraph.svg")

    nodes, edges = parse_dot(dot)
    cols = columnize(edges)

    # geometry
    COLX = {0: 250, 1: 600, 2: 880, 3: 1180}
    NODE_W, NODE_H, VGAP = 196, 46, 30
    TOP, TITLE_H = 96, 96
    rows = max((len(v) for v in cols.values()), default=1)
    H = TITLE_H + TOP + rows * (NODE_H + VGAP) + 70
    W = 1420

    pos = {}   # node id -> (cx, cy)
    for col, ids in cols.items():
        n = len(ids)
        total = n * NODE_H + (n - 1) * VGAP if n else 0
        y0 = TITLE_H + TOP + (rows * (NODE_H + VGAP) - VGAP - total) / 2
        for i, nid in enumerate(ids):
            cy = y0 + i * (NODE_H + VGAP) + NODE_H / 2
            pos[nid] = (COLX[col], cy)

    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{int(H)}" '
         f'viewBox="0 0 {W} {int(H)}" font-family="{FONT}">']
    s.append(f'<rect width="{W}" height="{int(H)}" fill="{BG}"/>')
    s.append('<defs><marker id="arr" markerWidth="9" markerHeight="9" refX="8" refY="3" '
             f'orient="auto"><path d="M0,0 L8,3 L0,6 z" fill="{GREY}"/></marker>'
             '<marker id="arrR" markerWidth="9" markerHeight="9" refX="8" refY="3" '
             f'orient="auto"><path d="M0,0 L8,3 L0,6 z" fill="{RED}"/></marker></defs>')
    # title
    s.append(f'<text x="40" y="38" font-size="17" fill="{WHITE}" font-weight="bold">'
             f'sotOs · Operator forensic view — sottrace_netgraph</text>')
    s.append(f'<text x="40" y="60" font-size="12" fill="{DIM}">'
             f'rendered from sottrace.netgraph.dot (the real tool\'s output). '
             f'RED = non-RFC1918 peer · the rightmost is the resident payload\'s C2 beacon.</text>')
    # column captions
    caps = {0: "inbound attackers", 1: "deception host", 2: "resident process", 3: "egress / C2"}
    for col, cap_txt in caps.items():
        s.append(f'<text x="{COLX[col]}" y="{TITLE_H+TOP-26}" font-size="11.5" fill="{DIM}" '
                 f'text-anchor="middle" font-style="italic">{esc(cap_txt)}</text>')

    # edges first (under nodes).  Stagger labels per-source so converging edges
    # (e.g. one attacker hitting :443 and :22) don't overprint at the sink.
    src_order = {}
    src_count = {}
    for src, dst, _ in edges:
        src_count[src] = src_count.get(src, 0) + 1
    for src, dst, label in edges:
        if src not in pos or dst not in pos:
            continue
        idx = src_order.get(src, 0); src_order[src] = idx + 1
        x1, y1 = pos[src]; x2, y2 = pos[dst]
        x1e = x1 + NODE_W / 2; x2e = x2 - NODE_W / 2
        egress = src.startswith("p") and dst.startswith("peer:")
        col = RED if egress else EDGE
        mk = "url(#arrR)" if egress else "url(#arr)"
        midx = (x1e + x2e) / 2
        s.append(f'<path d="M{x1e:.0f},{y1:.0f} C{midx:.0f},{y1:.0f} {midx:.0f},{y2:.0f} '
                 f'{x2e:.0f},{y2:.0f}" fill="none" stroke="{col}" stroke-width="1.6" '
                 f'marker-end="{mk}" opacity="0.9"/>')
        # label near the source end, stacked when one source has several edges
        n = src_count[src]
        lx = x1e + (x2e - x1e) * 0.34
        ly = y1 + (y2 - y1) * 0.34 + (idx - (n - 1) / 2) * 15 - 4
        s.append(f'<text x="{lx:.0f}" y="{ly:.0f}" font-size="10.5" '
                 f'fill="{RED if egress else BLUE}" text-anchor="middle">{esc(label)}</text>')

    # nodes
    for nid, (cx, cy) in pos.items():
        nd = nodes.get(nid, {"label": nid, "shape": "ellipse", "fill": None})
        red = nd.get("fill") == "red"
        stroke = RED if red else (GREY if nid == "honeypot" else "#2f3a4a")
        fill   = "#3a1414" if red else NODE_BG
        txtcol = RED if red else (WHITE if nid == "honeypot" else FG)
        x = cx - NODE_W / 2; y = cy - NODE_H / 2
        if nid == "honeypot":
            s.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{NODE_W}" height="{NODE_H}" rx="23" '
                     f'fill="{NODE_BG}" stroke="{GREY}" stroke-width="2.4"/>')
            s.append(f'<rect x="{x+4:.0f}" y="{y+4:.0f}" width="{NODE_W-8}" height="{NODE_H-8}" rx="19" '
                     f'fill="none" stroke="{GREY}" stroke-width="1"/>')
        elif nd["shape"] == "box":
            s.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{NODE_W}" height="{NODE_H}" rx="4" '
                     f'fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>')
        else:
            s.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{NODE_W}" height="{NODE_H}" rx="{NODE_H/2:.0f}" '
                     f'fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>')
        s.append(f'<text x="{cx:.0f}" y="{cy+4:.0f}" font-size="11.5" fill="{txtcol}" '
                 f'text-anchor="middle" font-weight="{"bold" if (red or nid=="honeypot") else "normal"}">'
                 f'{esc(nd["label"])}</text>')

    s.append('</svg>')
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(s))
    print(f"[render_netgraph] {len(nodes)} nodes, {len(edges)} edges -> {out}  ({W}x{int(H)})")

if __name__ == "__main__":
    main()
