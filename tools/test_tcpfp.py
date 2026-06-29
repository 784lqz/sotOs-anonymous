import os, struct, tempfile, subprocess, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))

# Real Linux TS-off SYN-ACK option block (captured from nginx:alpine, tcp_timestamps=0):
# MSS=1460, NOP, NOP, SACK_PERM, NOP, WS=10  → 12 bytes, no EOL.
OPTS = bytes([0x02,0x04,0x05,0xb4, 0x01,0x01, 0x04,0x02, 0x01, 0x03,0x03,0x0a])
assert len(OPTS) % 4 == 0
EXPECT_SIG_OS = "12:10:mss-nop-nop-sackperm-nop-ws"

def _synack_frame(ttl=64, df=True, ipid=0, window=64240, opts=OPTS,
                  src_port=443, dst_port=50000):
    tcp_hdr_len = 20 + len(opts)
    data_off = (tcp_hdr_len // 4) << 4
    tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, 1000, 2001,
                      data_off, 0x12, window, 0, 0) + opts   # 0x12 = SYN|ACK
    flags_frag = 0x4000 if df else 0x0000
    total = 20 + tcp_hdr_len
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ipid, flags_frag, ttl, 6, 0,
                     bytes([10,0,2,15]), bytes([10,0,2,2]))
    eth = b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x00\x00\x02\x08\x00"
    return eth + ip + tcp

def _write_pcap(path, frames, linktype=1):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for fr in frames:
            f.write(struct.pack("<IIII", 0, 0, len(fr), len(fr)) + fr)

def _run(frames, linktype=1):
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as t:
        path = t.name
    _write_pcap(path, frames, linktype)
    out = subprocess.check_output([sys.executable, os.path.join(HERE,"tcpfp.py"),"--json",path])
    os.unlink(path)
    return json.loads(out)

def test_synack_fields():
    r = _run([_synack_frame()])
    assert r["ttl"] == 64, r
    assert r["df"] == 1, r
    assert r["ip_id"] == 0, r
    assert r["window"] == 64240, r
    assert r["mss"] == 1460, r
    assert r["wscale"] == 10, r
    assert r["olayout"] == ["mss","nop","nop","sackperm","nop","ws"], r
    assert r["sig_os"] == EXPECT_SIG_OS, r
    assert r["sig"] == "64:12:1460:64240,10:mss-nop-nop-sackperm-nop-ws:df", r
    print("test_synack_fields OK")

def test_ignores_non_synack():
    syn = _synack_frame()
    tcp = struct.pack(">HHIIBBHHH", 443, 50000, 5, 6, (5<<4), 0x10, 8192, 0, 0)  # ACK only
    ip = struct.pack(">BBHHHBBH4s4s", 0x45,0,40,9,0x4000,64,6,0,bytes([10,0,2,15]),bytes([10,0,2,2]))
    ack = b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x00\x00\x02\x08\x00" + ip + tcp
    r = _run([ack, syn])    # ACK first; parser must skip to the SYN-ACK
    assert r["sig_os"] == EXPECT_SIG_OS, r
    print("test_ignores_non_synack OK")

def test_sll2():
    f = _synack_frame()
    sll2 = b"\x08\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x06"+b"\x00"*8+f[14:]
    r = _run([sll2], linktype=276)
    assert r["sig_os"] == EXPECT_SIG_OS and r["ttl"] == 64, r
    print("test_sll2 OK")

if __name__ == "__main__":
    test_synack_fields(); test_ignores_non_synack(); test_sll2()
