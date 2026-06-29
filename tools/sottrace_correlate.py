#!/usr/bin/env python3
"""sottrace_correlate.py — join a QEMU filter-dump pcap with a sottrace serial log.

THE CONTRACT (read this before trusting the output):
  * The pcap is QEMU's byte-exact wire (Pillar-1 TCP/TLS fingerprint preserved).
    Packets carry a WALL-CLOCK timestamp (libpcap record ts_sec.ts_usec).
  * The sottrace serial log carries OS-truth events stamped with the guest's
    rdtsc TSC (cycles), NOT wall-clock.
  * The ONLY authoritative join key is conn_id <-> 5-tuple: each sottrace
    INBOUND_ACCEPT line names (remote_ip, lport); we match the pcap flow whose
    (src_ip == remote_ip AND dst_port == lport). We do NOT join on absolute
    time.
  * We therefore render TWO correlated-but-separate clocks per conn: the wire
    packets ordered by pcap wall-clock, and the OS events ordered by sottrace
    TSC. We do NOT claim a single fused absolute timeline — the affine TSC->wall
    map is underdetermined (the serial log records no host wall-clock per
    tsc-anchor, so the slope can't be recovered). The tsc-anchor lines are
    parsed and reported only as a coarse ordering hint.

Stdlib only (struct/argparse) — no scapy/tshark dependency.
"""
import argparse
import os
import re
import struct
import sys

# ----------------------------------------------------------------------------
# (1) libpcap reader — linktype-aware, little-endian (QEMU filter-dump default).
# ----------------------------------------------------------------------------

def _l2_offset(linktype):
    """Bytes to skip before the IPv4 header for a given libpcap linktype."""
    if linktype == 1:      # LINKTYPE_ETHERNET — 14-byte L2 header
        return 14
    if linktype == 101:    # LINKTYPE_RAW — IP at offset 0
        return 0
    return None            # unsupported linktype


def read_pcap(path):
    """Return (packets, linktype). packets = list of dicts:
       {src_ip, dst_ip, src_port, dst_port, ts, payload_len, idx}.
       Tolerates a missing/empty/truncated file (returns [])."""
    if not path or not os.path.exists(path):
        return [], None
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return [], None
    if len(data) < 24:
        return [], None

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":        # us-resolution, little-endian
        end, usec_div = "<", 1
    elif magic == b"\xa1\xb2\xc3\xd4":      # us-resolution, big-endian
        end, usec_div = ">", 1
    elif magic == b"\x4d\x3c\xb2\xa1":      # ns-resolution, little-endian
        end, usec_div = "<", 1000
    elif magic == b"\xa1\xb2\x3c\x4d":      # ns-resolution, big-endian
        end, usec_div = ">", 1000
    else:
        # Not a libpcap file — tolerate gracefully.
        return [], None

    linktype = struct.unpack(end + "I", data[20:24])[0]
    l2 = _l2_offset(linktype)
    packets = []
    off = 24
    idx = 0
    while off + 16 <= len(data):
        ts_sec, ts_sub, incl, _orig = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + incl]
        off += incl
        if len(frame) < incl:
            break  # truncated final record
        if l2 is None:
            continue
        ip = frame[l2:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:   # not IPv4
            continue
        ihl = (ip[0] & 0x0f) * 4
        if ihl < 20 or ip[9] != 6:               # not TCP
            continue
        src_ip = "%d.%d.%d.%d" % (ip[12], ip[13], ip[14], ip[15])
        dst_ip = "%d.%d.%d.%d" % (ip[16], ip[17], ip[18], ip[19])
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        src_port = struct.unpack(">H", tcp[0:2])[0]
        dst_port = struct.unpack(">H", tcp[2:4])[0]
        doff = (tcp[12] >> 4) * 4
        payload_len = max(0, len(tcp) - doff)
        ts = ts_sec + (ts_sub / usec_div) / 1_000_000.0
        packets.append({
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "ts": ts, "payload_len": payload_len, "idx": idx,
        })
        idx += 1
    return packets, linktype


# ----------------------------------------------------------------------------
# (2) serial-log parser — anchor on the "[sottrace] " prefix to ride out noise.
# ----------------------------------------------------------------------------

# tsc-anchor line:  [sottrace] tsc-anchor tsc=<T>
RE_ANCHOR = re.compile(r"\[sottrace\]\s+tsc-anchor\s+tsc=(\d+)")

# Any sottrace event line carries a leading tsc=<T> (NOT the anchor variant).
RE_EVENT = re.compile(r"\[sottrace\]\s+tsc=(\d+)\s+(.*)$")

# INBOUND_ACCEPT (trace.c SG_EV_INBOUND_ACCEPT formatter):
#   pid=<p> conn=<id> ACCEPT from <a.b.c.d>:<port> -> :<lport>
RE_ACCEPT = re.compile(
    r"pid=(\d+)\s+conn=(\d+)\s+ACCEPT\s+from\s+"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+:(\d+)")

# Any event carrying conn=<id> (ACCEPT, CLOSE, RESPONSE_PROFILE, CANARY_SCREENSHOT, ...).
RE_CONN = re.compile(r"conn=(\d+)")


def parse_log(path):
    """Return (anchors, events). anchors = [tsc...]; events = list of dicts:
       {tsc, conn_id (or None), accept (or None), text, lineno}.
       'accept' = {remote_ip, remote_port, lport, pid} when the line is an ACCEPT."""
    anchors = []
    events = []
    if not path or not os.path.exists(path):
        return anchors, events
    with open(path, "rb") as f:
        raw = f.read()
    # Serial logs can carry truncated multibyte / control noise — decode lenient.
    text = raw.decode("utf-8", "replace")
    for lineno, line in enumerate(text.splitlines(), 1):
        if "[sottrace] " not in line:
            continue
        m = RE_ANCHOR.search(line)
        if m:
            anchors.append(int(m.group(1)))
            continue
        m = RE_EVENT.search(line)
        if not m:
            continue
        tsc = int(m.group(1))
        rest = m.group(2)
        conn_id = None
        accept = None
        ma = RE_ACCEPT.search(rest)
        if ma:
            accept = {
                "pid": int(ma.group(1)),
                "remote_ip": ma.group(3),
                "remote_port": int(ma.group(4)),
                "lport": int(ma.group(5)),
            }
            conn_id = int(ma.group(2))
        else:
            mc = RE_CONN.search(rest)
            if mc:
                conn_id = int(mc.group(1))
        events.append({
            "tsc": tsc, "conn_id": conn_id, "accept": accept,
            "text": rest.strip(), "lineno": lineno,
        })
    return anchors, events


# ----------------------------------------------------------------------------
# (3) JOIN by conn_id <-> 5-tuple.
# ----------------------------------------------------------------------------

def correlate(packets, events):
    """Return (conn_blocks, orphans).
       conn_blocks: ordered list of {conn_id, accept, events[], packets[]}.
       orphans: OS events with no conn_id (TSC order)."""
    # Group events by conn_id; remember first-seen order for deterministic output.
    by_conn = {}
    order = []
    orphans = []
    for ev in events:
        cid = ev["conn_id"]
        if cid is None:
            orphans.append(ev)
            continue
        if cid not in by_conn:
            by_conn[cid] = {"conn_id": cid, "accept": None, "events": []}
            order.append(cid)
        by_conn[cid]["events"].append(ev)
        if ev["accept"] is not None and by_conn[cid]["accept"] is None:
            by_conn[cid]["accept"] = ev["accept"]

    conn_blocks = []
    for cid in order:
        blk = by_conn[cid]
        blk["events"].sort(key=lambda e: e["tsc"])
        acc = blk["accept"]
        matched = []
        if acc is not None:
            # Authoritative key: pcap flow whose src_ip == remote_ip AND
            # dst_port == lport. (Both directions of the flow are kept so the
            # block shows the full wire exchange.)
            rip, lport, rport = acc["remote_ip"], acc["lport"], acc["remote_port"]
            for p in packets:
                fwd = (p["src_ip"] == rip and p["dst_port"] == lport)
                rev = (p["dst_ip"] == rip and p["src_port"] == lport)
                if fwd or rev:
                    matched.append(p)
            matched.sort(key=lambda p: (p["ts"], p["idx"]))
        blk["packets"] = matched
        conn_blocks.append(blk)
    orphans.sort(key=lambda e: e["tsc"])
    return conn_blocks, orphans


# ----------------------------------------------------------------------------
# (4) emit timeline.txt
# ----------------------------------------------------------------------------

HEADER = """\
================================================================================
sottrace correlated timeline
================================================================================
CONTRACT:
  * Wire packets are shown in pcap WALL-CLOCK order (libpcap record ts).
  * OS events are shown in sottrace TSC order (rdtsc cycles, NOT wall-clock).
  * Packets and OS events are JOINED BY conn_id <-> 5-tuple (INBOUND_ACCEPT's
    remote-ip + local-port matched against the pcap flow). This conn_id join is
    the ONLY authoritative correlation key.
  * NO single fused absolute timeline is claimed: the TSC<->wall affine map is
    underdetermined (the log carries no host wall-clock per tsc-anchor). The
    two clocks are correlated-but-separate.
================================================================================
"""


def write_timeline(out_path, conn_blocks, orphans, anchors, packets, linktype):
    lines = [HEADER]
    lt = {1: "ETHERNET", 101: "RAW"}.get(linktype, str(linktype))
    lines.append("pcap linktype : %s" % (lt if linktype is not None else "(none / no pcap)"))
    lines.append("pcap packets  : %d" % len(packets))
    lines.append("tsc-anchors   : %s" % (
        ", ".join(str(a) for a in anchors) if anchors else "(none)"))
    lines.append("")

    joined = [b for b in conn_blocks if b["packets"]]
    lines.append("CONNECTIONS (joined by conn_id): %d total, %d with matched wire flow"
                 % (len(conn_blocks), len(joined)))
    lines.append("")

    for blk in conn_blocks:
        cid = blk["conn_id"]
        acc = blk["accept"]
        lines.append("-" * 80)
        if acc:
            lines.append("conn_id=%d  ACCEPT from %s:%d -> :%d  (pid=%d)"
                         % (cid, acc["remote_ip"], acc["remote_port"],
                            acc["lport"], acc["pid"]))
        else:
            lines.append("conn_id=%d  (no INBOUND_ACCEPT seen — cannot match wire flow)"
                         % cid)
        lines.append("")
        lines.append("  WIRE PACKETS (pcap wall-clock order): %d" % len(blk["packets"]))
        for p in blk["packets"]:
            lines.append("    [wall %.6f] %s:%d -> %s:%d  tcp_payload=%dB"
                         % (p["ts"], p["src_ip"], p["src_port"],
                            p["dst_ip"], p["dst_port"], p["payload_len"]))
        lines.append("")
        lines.append("  OS EVENTS (sottrace TSC order): %d" % len(blk["events"]))
        for ev in blk["events"]:
            lines.append("    [tsc %d] %s" % (ev["tsc"], ev["text"]))
        lines.append("")

    lines.append("=" * 80)
    lines.append("OS-only events (no conn_id; TSC order): %d" % len(orphans))
    lines.append("  e.g. ISOLATED_WRITE_DROP / CANARY_SCREENSHOT / FORKBOMB_QUARANTINED / syscalls")
    lines.append("")
    for ev in orphans:
        lines.append("    [tsc %d] %s" % (ev["tsc"], ev["text"]))
    lines.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main(argv):
    ap = argparse.ArgumentParser(
        description="Join a QEMU pcap with a sottrace serial log by conn_id "
                    "(host, stdlib only). Wire packets stay in pcap wall-clock "
                    "order; OS events stay in TSC order; no fused absolute "
                    "timeline is claimed.")
    ap.add_argument("--log", required=True, help="sottrace serial.log")
    ap.add_argument("--pcap", default="/tmp/honeypot.pcap",
                    help="QEMU filter-dump pcap (default: /tmp/honeypot.pcap)")
    ap.add_argument("--out", default="timeline.txt",
                    help="output timeline path (default: timeline.txt)")
    args = ap.parse_args(argv[1:])

    packets, linktype = read_pcap(args.pcap)
    anchors, events = parse_log(args.log)
    conn_blocks, orphans = correlate(packets, events)
    joined = [b for b in conn_blocks if b["packets"]]

    write_timeline(args.out, conn_blocks, orphans, anchors, packets, linktype)

    print("[correlate] %d packets, %d events, %d conns joined"
          % (len(packets), len(events), len(joined)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
