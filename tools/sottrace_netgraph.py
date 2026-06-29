#!/usr/bin/env python3
"""sottrace netgraph — render captured connections as a Graphviz process<->peer graph.

Input: a serial log (argv[1]) carrying the always-on live-drain sottrace lines. Two
classes of connection are rendered around a central `honeypot` node:

  INBOUND (response_profiles served to attackers) — joined per conn_id from three lines:
    [sottrace] tsc=<d> pid=<d> conn=<id> ACCEPT from <a.b.c.d>:<port> -> :<lport>
    [sottrace] tsc=<d> pid=<d> conn=<id> RESPONSE_PROFILE <PROTO> :<port> served <d> bytes
    [sottrace] tsc=<d> pid=<d> conn=<id> CLOSE rx=<d> tx=<d>
  → one edge `peer:<ip> -> honeypot` labelled `<proto> :<lport> rx=<rx>B`.

  EGRESS (outbound connect — possible C2 beacon) from trace_emit_net (Task B):
    [sottrace] tsc=<d> pid=<d> NET CONNECT <a.b.c.d>:<port> bytes=<d> conn=<d>
  → one edge `p<pid> -> peer:<ip>:<port>` labelled `CONNECT`.

Peer nodes are ellipses; **non-RFC1918** peers (NOT 10/8, NOT 172.16/12, NOT
192.168/16) are filled RED — flagged as likely C2. Process nodes (egress pids) are
boxes.

Emits `sottrace.netgraph.dot` and prints `[netgraph] <C> conns, <P> peers, <E> edges`.
Tolerant of arbitrary interleaved noise; exits 0 even on 0 matches.

Stdlib only — no graphviz/pydot dependency (it emits the .dot text directly).
"""
import re, sys

# INBOUND ACCEPT (trace.c SG_EV_INBOUND_ACCEPT):
#   conn=<id> ACCEPT from <a.b.c.d>:<port> -> :<lport>
RE_ACCEPT = re.compile(
    r"\bconn=(\d+)\s+ACCEPT\s+from\s+"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+:(\d+)")

# RESPONSE_PROFILE (trace.c SG_EV_*RESPONSE_PROFILE):  conn=<id> RESPONSE_PROFILE <PROTO> :<port> served <d> bytes
RE_RESPONSE_PROFILE = re.compile(
    r"\bconn=(\d+)\s+RESPONSE_PROFILE\s+(\w+)\s+:(\d+)\s+served\s+(\d+)\s+bytes")

# CLOSE (trace.c SG_EV_CONN_CLOSE):  conn=<id> CLOSE rx=<d> tx=<d>
RE_CLOSE = re.compile(
    r"\bconn=(\d+)\s+CLOSE\s+rx=(\d+)\s+tx=(\d+)")

# EGRESS NET (trace.c SG_EV_NET_*, Task B):
#   pid=<d> NET <CONNECT|SEND|RECV> <a.b.c.d>:<port> bytes=<d> conn=<d>
# Confirmed against trace.c:278 format string (field order tsc,pid,op,ip:port,bytes,conn).
RE_NET = re.compile(
    r"pid=(\d+)\s+NET\s+(CONNECT|SEND|RECV)\s+"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+bytes=(\d+)\s+conn=(\d+)")


def _esc(s):
    """Escape a string for a double-quoted Graphviz label/id."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def is_rfc1918(ip):
    """True if ip is an RFC1918 private address (10/8, 172.16/12, 192.168/16)."""
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
    except (ValueError, AttributeError):
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


def parse(path):
    """Parse the log; return (conns, egress).

    conns:  {conn_id: {ip, peer_port, lport, proto, rx, tx, served}} (inbound)
    egress: list of {pid, ip, port} (one per NET CONNECT)
    """
    conns = {}
    egress = []
    seen_egress = set()
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = RE_ACCEPT.search(line)
            if m:
                cid = int(m.group(1))
                c = conns.setdefault(cid, {})
                c["ip"] = m.group(2)
                c["peer_port"] = int(m.group(3))
                c["lport"] = int(m.group(4))
                continue
            m = RE_RESPONSE_PROFILE.search(line)
            if m:
                cid = int(m.group(1))
                c = conns.setdefault(cid, {})
                c["proto"] = m.group(2)
                c.setdefault("lport", int(m.group(3)))
                c["served"] = int(m.group(4))
                continue
            m = RE_CLOSE.search(line)
            if m:
                cid = int(m.group(1))
                c = conns.setdefault(cid, {})
                c["rx"] = int(m.group(2))
                c["tx"] = int(m.group(3))
                continue
            m = RE_NET.search(line)
            if m:
                # SEND/RECV are skipped at the emit site (YAGNI) but parse defensively:
                # only CONNECT defines an egress edge.
                if m.group(2) != "CONNECT":
                    continue
                pid = int(m.group(1))
                ip = m.group(3)
                port = int(m.group(4))
                key = (pid, ip, port)
                if key in seen_egress:
                    continue
                seen_egress.add(key)
                egress.append({"pid": pid, "ip": ip, "port": port})
                continue
    return conns, egress


def build_dot(conns, egress):
    """Render inbound conns + egress connects into a Graphviz .dot document string.

    Returns (dot_text, n_conns, n_peers, n_edges).
    """
    # Only inbound conns that actually have a peer ip (an ACCEPT) count as conns.
    inbound = {cid: c for cid, c in conns.items() if c.get("ip")}

    peers = {}  # peer node id -> ip (for RFC1918 classification)
    edges = []  # (src_id, dst_id, label)

    lines = ["digraph sottrace_net {", "  rankdir=LR;",
             '  "honeypot" [label="honeypot", shape=doublecircle, '
             'fillcolor=lightgrey, style=filled];']

    # inbound edges: peer:<ip> -> honeypot
    for cid in sorted(inbound):
        c = inbound[cid]
        ip = c["ip"]
        pid_node = "peer:%s" % ip
        peers.setdefault(pid_node, ip)
        proto = c.get("proto", "?")
        lport = c.get("lport", 0)
        rx = c.get("rx")
        if rx is None:
            rx = c.get("served", 0)
        label = "%s :%d rx=%dB" % (proto, lport, rx)
        edges.append((pid_node, "honeypot", label))

    # egress edges: p<pid> -> peer:<ip>:<port>
    procs = {}  # process node id -> pid
    for e in egress:
        pid = e["pid"]
        ip = e["ip"]
        port = e["port"]
        proc_node = "p%d" % pid
        procs[proc_node] = pid
        peer_node = "peer:%s:%d" % (ip, port)
        peers.setdefault(peer_node, ip)
        edges.append((proc_node, peer_node, "CONNECT"))

    # process nodes (boxes)
    for proc_node in sorted(procs):
        lines.append('  "%s" [label="%s", shape=box];'
                     % (_esc(proc_node), _esc(proc_node)))

    # peer nodes (ellipses; non-RFC1918 filled red = C2)
    for peer_node in sorted(peers):
        ip = peers[peer_node]
        if is_rfc1918(ip):
            lines.append('  "%s" [label="%s", shape=ellipse];'
                         % (_esc(peer_node), _esc(peer_node)))
        else:
            lines.append(
                '  "%s" [label="%s (C2?)", shape=ellipse, '
                'fillcolor=red, style=filled];'
                % (_esc(peer_node), _esc(peer_node)))

    # edges
    for (src, dst, label) in edges:
        lines.append('  "%s" -> "%s" [label="%s"];'
                     % (_esc(src), _esc(dst), _esc(label)))

    lines.append("}")
    return "\n".join(lines) + "\n", len(inbound), len(peers), len(edges)


def main(argv):
    if len(argv) < 2:
        print("usage: sottrace_netgraph.py <serial.log>", file=sys.stderr)
        return 2
    try:
        conns, egress = parse(argv[1])
    except OSError as ex:
        print("error: %s" % ex, file=sys.stderr)
        return 2
    dot, nconns, npeers, nedges = build_dot(conns, egress)
    with open("sottrace.netgraph.dot", "w") as f:
        f.write(dot)
    print("[netgraph] %d conns, %d peers, %d edges" % (nconns, npeers, nedges))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
