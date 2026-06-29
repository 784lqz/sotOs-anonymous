#!/usr/bin/env python3
"""Host TDD for tools/ipfp.py — synthetic frames, no pcap needed."""
import struct, ipfp

def _ip(proto, ident, flags_frag, ttl, payload):
    vihl = 0x45
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", vihl, 0, total, ident, flags_frag, ttl,
                      proto, 0, b"\x0a\x00\x02\x02", b"\x0a\x00\x02\x0f")
    return hdr + payload

def _eth(ip):
    return b"\x52"*6 + b"\x52"*6 + b"\x08\x00" + ip

def test_icmp_reply():
    icmp = struct.pack("!BBHHH", 0, 0, 0, 1, 1)   # type 0 (reply), code 0
    frame = _eth(_ip(1, 0, 0x4000, 64, icmp))
    r = ipfp.parse_icmp(frame)
    assert r == {"ip_id": 0, "df": 1, "ttl": 64, "icmp_type": 0}, r

def test_rst():
    # RST|ACK from source port 99 (closed guest port), seq=0, ack=1001, window=0
    tcp = struct.pack("!HHIIBBHHH", 99, 40000, 0, 1001, (5<<4), 0x14, 0, 0, 0)
    frame = _eth(_ip(6, 0, 0x4000, 64, tcp))
    r = ipfp.parse_rst(frame)
    assert r == {"ip_id": 0, "df": 1, "ttl": 64, "flags": 0x14,
                 "seq": 0, "ack": 1001, "window": 0}, r

def test_tcp_synack_and_data():
    # SYN-ACK from :80, ip_id 0 (atomic); then a data/PSH-ACK seg, ip_id incrementing.
    sa = struct.pack("!HHIIBBHHH", 80, 5000, 99, 1, (5<<4), 0x12, 64240, 0, 0)
    fr_sa = _eth(_ip(6, 0, 0x4000, 64, sa))
    t = ipfp.parse_tcp(fr_sa)
    assert t["src_port"] == 80 and t["ip_id"] == 0 and t["flags"] == 0x12 and t["df"] == 1, t
    data = struct.pack("!HHIIBBHHH", 80, 5000, 100, 1, (5<<4), 0x18, 64240, 0, 0) + b"hello"
    fr_d = _eth(_ip(6, 7777, 0x4000, 64, data))
    t = ipfp.parse_tcp(fr_d)
    assert t["src_port"] == 80 and t["ip_id"] == 7777 and t["df"] == 1, t

if __name__ == "__main__":
    test_icmp_reply(); test_rst(); test_tcp_synack_and_data()
    print("[test_ipfp] OK")
