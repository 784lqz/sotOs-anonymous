#!/usr/bin/env python3
"""TCP/IP SYN-ACK fingerprint parser — extract the server's passive (p0f-style)
signature from a pcap. Finds the first SYN+ACK from the server port and reports
the IP/TCP fingerprint fields, a full `sig`, and the OS-discriminating `sig_os`
(option layout + wscale; MSS/window excluded — they are path-dependent).
Stdlib only (struct) — no scapy/tshark.
"""
import os, struct, sys, json

def _l2_strip(frame, linktype):
    if linktype == 1:                       # EN10MB
        if len(frame) < 14 or frame[12:14] != b"\x08\x00": return None
        return frame[14:]
    if linktype == 113:                     # LINUX_SLL
        if len(frame) < 16 or frame[14:16] != b"\x08\x00": return None
        return frame[16:]
    if linktype == 276:                     # LINUX_SLL2
        if len(frame) < 20 or frame[0:2] != b"\x08\x00": return None
        return frame[20:]
    return None

def _decode_opts(opts):
    layout = []; mss = None; wscale = None
    i = 0
    while i < len(opts):
        k = opts[i]
        if k == 0: layout.append("eol"); break
        if k == 1: layout.append("nop"); i += 1; continue
        if i + 1 >= len(opts): break
        ln = opts[i+1]
        if ln < 2 or i + ln > len(opts): break
        body = opts[i+2:i+ln]
        if k == 2 and ln == 4: mss = struct.unpack(">H", body[:2])[0]; layout.append("mss")
        elif k == 3 and ln == 3: wscale = body[0]; layout.append("ws")
        elif k == 4 and ln == 2: layout.append("sackperm")
        elif k == 8: layout.append("ts")
        else: layout.append("kind%d" % k)
        i += ln
    return layout, mss, wscale

def synack_fp(path):
    with open(path, "rb") as f:
        data = f.read()
    server_port = int(os.environ.get("TCPFP_SERVER_PORT", "443"))
    magic = data[:4]
    le = magic == b"\xd4\xc3\xb2\xa1"
    if not le and magic != b"\xa1\xb2\xc3\xd4":
        raise ValueError("not a libpcap file (bad magic %r)" % magic)
    end = "<" if le else ">"
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        _, _, incl, _o = struct.unpack(end + "IIII", data[off:off+16])
        off += 16
        frame = data[off:off+incl]; off += incl
        ip = _l2_strip(frame, linktype)
        if not ip or len(ip) < 20 or (ip[0] >> 4) != 4: continue
        ihl = (ip[0] & 0x0f) * 4
        if ip[9] != 6: continue
        tos = ip[1]
        ip_id = struct.unpack(">H", ip[4:6])[0]
        flags_frag = struct.unpack(">H", ip[6:8])[0]
        df = 1 if (flags_frag & 0x4000) else 0
        ttl = ip[8]
        tcp = ip[ihl:]
        if len(tcp) < 20: continue
        src_port = struct.unpack(">H", tcp[0:2])[0]
        flags = tcp[13]
        if src_port != server_port or (flags & 0x12) != 0x12: continue   # need SYN+ACK
        window = struct.unpack(">H", tcp[14:16])[0]
        doff = (tcp[12] >> 4) * 4
        if doff < 20 or doff > len(tcp): continue   # malformed/truncated header
        opts = tcp[20:doff]
        layout, mss, wscale = _decode_opts(opts)
        quirks = []
        if df: quirks.append("df")
        if ip_id != 0: quirks.append("id+")
        ws_s = ("%d" % wscale) if wscale is not None else "*"
        mss_s = ("%d" % mss) if mss is not None else "*"
        sig = "%d:%d:%s:%d,%s:%s:%s" % (ttl, len(opts), mss_s, window, ws_s,
                                        "-".join(layout), ",".join(quirks) or "none")
        # sig_os: kernel-determined, path-independent (NO mss, NO raw window).
        sig_os = "%d:%s:%s" % (len(opts), ws_s, "-".join(layout))
        return {"ttl": ttl, "df": df, "ip_id": ip_id, "tos": tos, "window": window,
                "olen": len(opts), "mss": mss, "wscale": wscale, "olayout": layout,
                "quirks": quirks, "sig": sig, "sig_os": sig_os}
    raise ValueError("no SYN+ACK from server port %d found" % server_port)

def main(argv):
    as_json = "--json" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not args:
        print("usage: tcpfp.py [--json] <capture.pcap>", file=sys.stderr); return 2
    r = synack_fp(args[0])
    if as_json:
        print(json.dumps(r))
    else:
        print("sig_os   = %s   <-- OS-discriminating (the gate)" % r["sig_os"])
        print("sig      = %s" % r["sig"])
        print("ttl=%d df=%d ip_id=%d tos=%d window=%d mss=%s wscale=%s"
              % (r["ttl"], r["df"], r["ip_id"], r["tos"], r["window"], r["mss"], r["wscale"]))
        print("olayout  = %s" % " ".join(r["olayout"]))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
