#!/usr/bin/env python3
"""sottrace graph — render sottrace FS events as a Graphviz process->file graph.

Input: a serial log (argv[1]) carrying `G pid=<d> tier=<d> op=<OP> bytes=<d> path=<rest>`
lines (the `sottrace graph` command output, emitted between `[graph] BEGIN`/`[graph] END`,
matching the in-orch `G pid=%u tier=%d op=%s bytes=%llu path=%s` format from Task B1). The
same `G pid=` form may also appear in the live-drain output; this tool accepts the `G pid=`
line wherever it lands and is tolerant of arbitrary leading noise on the line.

Aggregates per (pid, path, op) summing bytes, tracks per-pid tier (max seen), and emits
`sottrace.dot`: process box nodes (Tier-2+ filled salmon), file ellipse nodes, and one edge
per (pid, path, op) labelled `<op> <bytes>B`.

Stdlib only — no graphviz/pydot dependency (it emits the .dot text directly).
"""
import re, sys

# `G pid=<d> tier=<d> op=<OPEN|READ|WRITE> bytes=<d> path=<rest>` — the `sottrace graph`
# command's [graph] block. Tolerant of leading noise; path is the rest of the line.
G_RE = re.compile(
    r"G\s+pid=(\d+)\s+tier=(-?\d+)\s+op=(\w+)\s+bytes=(\d+)\s+path=(.*)$"
)
# `[sottrace] tsc=<d> pid=<d> FS <OPEN|READ|WRITE> bytes=<d> path=<rest>` — the LIVE-DRAIN
# FS format (sottrace_format_line). No tier on these → tier 0. Captures all streamed disk
# activity (incl. malware persistence: crontab / systemd backdoor.* / .bashrc writes).
FS_RE = re.compile(
    r"pid=(\d+)\s+FS\s+(OPEN|READ|WRITE)\s+bytes=(\d+)\s+path=(.*)$"
)


def _esc(s):
    """Escape a string for a double-quoted Graphviz label/id."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def parse(path):
    """Parse the log; return (agg, tiers).

    agg:   {(pid, path, op): total_bytes}
    tiers: {pid: max_tier_seen}
    """
    agg = {}
    tiers = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = G_RE.search(line)
            if m:
                pid, tier, op = int(m.group(1)), int(m.group(2)), m.group(3)
                nbytes, fpath = int(m.group(4)), m.group(5).rstrip("\r\n").strip()
            else:
                m = FS_RE.search(line)
                if not m:
                    continue
                pid, tier, op = int(m.group(1)), 0, m.group(2)
                nbytes, fpath = int(m.group(3)), m.group(4).rstrip("\r\n").strip()
            if not fpath:
                continue
            key = (pid, fpath, op)
            agg[key] = agg.get(key, 0) + nbytes
            if pid not in tiers or tier > tiers[pid]:
                tiers[pid] = tier
    return agg, tiers


def build_dot(agg, tiers):
    """Render the aggregate into a Graphviz .dot document string."""
    pids = sorted(tiers)
    files = sorted({fpath for (_pid, fpath, _op) in agg})
    lines = ["digraph sottrace {", "  rankdir=LR;"]
    # process nodes
    for pid in pids:
        t = tiers[pid]
        label = "pid %d\\ntier %d" % (pid, t)
        if t >= 2:
            lines.append(
                '  "p%d" [label="%s", shape=box, fillcolor=salmon, style=filled];'
                % (pid, label)
            )
        else:
            lines.append('  "p%d" [label="%s", shape=box];' % (pid, label))
    # file nodes
    for fpath in files:
        lines.append('  "f:%s" [label="%s", shape=ellipse];' % (_esc(fpath), _esc(fpath)))
    # edges
    edges = sorted(agg)
    for (pid, fpath, op) in edges:
        nbytes = agg[(pid, fpath, op)]
        lines.append(
            '  "p%d" -> "f:%s" [label="%s %dB"];' % (pid, _esc(fpath), op, nbytes)
        )
    lines.append("}")
    return "\n".join(lines) + "\n", len(pids), len(files), len(edges)


def main(argv):
    if len(argv) < 2:
        print("usage: sottrace_graph.py <serial.log>", file=sys.stderr)
        return 2
    agg, tiers = parse(argv[1])
    dot, nprocs, nfiles, nedges = build_dot(agg, tiers)
    with open("sottrace.dot", "w") as f:
        f.write(dot)
    print("[ok] sottrace.dot: %d procs, %d files, %d edges" % (nprocs, nfiles, nedges))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
