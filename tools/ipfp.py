#!/usr/bin/env python3
"""ipfp — stdlib pcap parser for ICMP-echo-reply + TCP IP/TCP fingerprint fields
(arc β). Mirrors tools/tcpfp.py's libpcap handling: no scapy/tshark.
parse_icmp/parse_rst/parse_tcp take a single Ethernet frame (bytes).
Usage:
  ipfp.py <pcap>                  -> first ICMP-reply + first RST
  ipfp.py <pcap> --rst-sport N    -> first RST whose SOURCE port == N (the closed guest port)
  ipfp.py <pcap> --tcp-ipids N    -> the IP-ID + flags of every TCP segment with SOURCE port N
                                     (the guest's :80 egress: SYN-ACK ip_id 0, data segs incrementing)
"""
import struct, sys

def _l2_strip(linktype, data):
    # EN10MB=1 (14B eth). LINUX_SLL=113 (16B). LINUX_SLL2=276 (20B). Mirror tcpfp.py.
    if linktype == 1:   return data[14:], data[12:14]
    if linktype == 113: return data[16:], data[14:16]
    if linktype == 276: return data[20:], data[0:2]
    return data[14:], data[12:14]

def _ip_fields(ipdata):
    ihl = (ipdata[0] & 0x0F) * 4
    ident = struct.unpack("!H", ipdata[4:6])[0]
    flags_frag = struct.unpack("!H", ipdata[6:8])[0]
    df = 1 if (flags_frag & 0x4000) else 0
    ttl = ipdata[8]
    proto = ipdata[9]
    return ihl, ident, df, ttl, proto, ipdata[ihl:]

def parse_icmp(frame, linktype=1):
    ipdata, _et = _l2_strip(linktype, frame)
    ihl, ident, df, ttl, proto, payload = _ip_fields(ipdata)
    if proto != 1 or len(payload) < 1:
        return None
    return {"ip_id": ident, "df": df, "ttl": ttl, "icmp_type": payload[0]}

def parse_tcp(frame, linktype=1):
    """Any TCP segment -> IP/TCP fingerprint fields (or None)."""
    ipdata, _et = _l2_strip(linktype, frame)
    ihl, ident, df, ttl, proto, payload = _ip_fields(ipdata)
    if proto != 6 or len(payload) < 20:
        return None
    sport, dport = struct.unpack("!HH", payload[0:4])
    seq, ack = struct.unpack("!II", payload[4:12])
    flags = payload[13]
    window = struct.unpack("!H", payload[14:16])[0]
    return {"ip_id": ident, "df": df, "ttl": ttl, "flags": flags,
            "src_port": sport, "dst_port": dport,
            "seq": seq, "ack": ack, "window": window}

def parse_rst(frame, linktype=1):
    t = parse_tcp(frame, linktype)
    if not t or not (t["flags"] & 0x04):   # RST bit
        return None
    return {"ip_id": t["ip_id"], "df": t["df"], "ttl": t["ttl"],
            "flags": t["flags"], "seq": t["seq"], "ack": t["ack"],
            "window": t["window"]}

def _frames(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24: return
        magic = struct.unpack("<I", gh[:4])[0]
        le = magic in (0xa1b2c3d4, 0xa1b23c4d)
        endi = "<" if le else ">"
        linktype = struct.unpack(endi + "I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16: break
            _ts, _us, caplen, _orig = struct.unpack(endi + "IIII", ph)
            data = f.read(caplen)
            if len(data) < caplen: break
            yield linktype, data

def main(argv):
    if len(argv) < 2:
        print("usage: ipfp.py <pcap> [--rst-sport N | --tcp-ipids N]", file=sys.stderr); return 2
    path = argv[1]
    # --tcp-ipids N : list every guest-egress TCP segment from source port N
    if len(argv) >= 4 and argv[2] == "--tcp-ipids":
        sport = int(argv[3]); rows = []
        for lt, d in _frames(path):
            t = parse_tcp(d, lt)
            if t and t["src_port"] == sport:
                rows.append(t)
        for t in rows:
            print("[ipfp] tcp src=%d flags=0x%02x ip_id=%d df=%d ttl=%d"
                  % (t["src_port"], t["flags"], t["ip_id"], t["df"], t["ttl"]))
        ids = [t["ip_id"] for t in rows]
        print("[ipfp] tcp_ipids src=%d -> %s" % (sport, ids))
        return 0
    # --rst-sport N : the RST whose SOURCE port is N (the closed guest port)
    rst_sport = None
    if len(argv) >= 4 and argv[2] == "--rst-sport":
        rst_sport = int(argv[3])
    icmp = rst = None
    for lt, d in _frames(path):
        if icmp is None:
            r = parse_icmp(d, lt)
            if r and r["icmp_type"] == 0: icmp = r   # echo reply
        if rst is None:
            t = parse_tcp(d, lt)
            if t and (t["flags"] & 0x04) and (rst_sport is None or t["src_port"] == rst_sport):
                rst = parse_rst(d, lt)
    print("[ipfp] icmp_reply:", icmp)
    print("[ipfp] rst:", rst)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
