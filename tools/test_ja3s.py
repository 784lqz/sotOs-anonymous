import os, struct, tempfile, hashlib, subprocess, sys, json

TLS12 = 0x0303
CIPHER = 0xc02f
EXTS = [0xff01, 0x0000]  # renegotiation_info, server_name
EXPECT_STRING = "771,49199,65281-0"
EXPECT_MD5 = hashlib.md5(EXPECT_STRING.encode()).hexdigest()
HERE = os.path.dirname(os.path.abspath(__file__))

def _server_hello_body():
    b = struct.pack(">H", TLS12) + b"\x11" * 32 + b"\x00"   # version, random, sid len 0
    b += struct.pack(">H", CIPHER) + b"\x00"                # cipher, compression null
    ext = b"".join(struct.pack(">HH", et, 0) for et in EXTS)
    return b + struct.pack(">H", len(ext)) + ext

def _handshake_record():
    body = _server_hello_body()
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body   # type=2 + 3-byte len
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs # content=22, ver, len

def _ip_tcp(payload, src_port, dst_port, seq):
    tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, seq, 0, 0x50, 0x18, 0xffff, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     bytes([10,0,2,15]), bytes([10,0,2,2]))
    return ip + tcp + payload

def _eth(payload):    # linktype 1
    return b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x00\x00\x02\x08\x00" + payload

def _sll2(payload):   # linktype 276: 2B proto, 2B rsvd, 4B ifindex, 2B arphrd, 1B pkttype, 1B addrlen, 8B addr
    return b"\x08\x00" + b"\x00\x00" + b"\x00\x00\x00\x01" + b"\x00\x00" + b"\x00" + b"\x06" + b"\x00"*8 + payload

def _write_pcap(path, frames, linktype=1):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for fr in frames:
            f.write(struct.pack("<IIII", 0, 0, len(fr), len(fr)) + fr)

def _run(frames, linktype=1):
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as t:
        path = t.name
    _write_pcap(path, frames, linktype)
    out = subprocess.check_output([sys.executable, os.path.join(HERE, "ja3s.py"), "--json", path])
    os.unlink(path)
    return json.loads(out)

def _assert_expected(res):
    assert res["version"] == 771, res
    assert res["cipher"] == 0xc02f, res
    assert res["extensions"] == [0xff01, 0x0000], res
    assert res["ja3s_string"] == EXPECT_STRING, res
    assert res["ja3s"] == EXPECT_MD5, res

def test_single():
    _assert_expected(_run([_eth(_ip_tcp(_handshake_record(), 443, 50000, 1000))]))
    print("test_single OK")

def test_two_connections():
    # Two server flows to :443 from distinct client ports, with very different
    # random ISNs. A seq-only reassembler would interleave them and corrupt the
    # ServerHello; the 4-tuple grouping must keep each flow intact.
    f1 = _eth(_ip_tcp(_handshake_record(), 443, 50001, 0xF0000000))
    f2 = _eth(_ip_tcp(_handshake_record(), 443, 50002, 0x00000010))
    _assert_expected(_run([f1, f2]))   # both flows are identical ServerHellos → same result
    _assert_expected(_run([f2, f1]))   # order-independent / deterministic
    print("test_two_connections OK")

def test_sll2():
    _assert_expected(_run([_sll2(_ip_tcp(_handshake_record(), 443, 50000, 1000))], linktype=276))
    print("test_sll2 OK")

# --- TLS 1.3 JA3S + JA4S goldens (ε4 — pinned oracle constants) -------------
#
# The sotOs hand-rolled 1.3 ServerHello emits exactly the ext list
# [0x002b supported_versions, 0x0033 key_share] (byte-exact with nginx). For
# that ext list the JA4S ext-hash is ALWAYS a56c5b993250, JA4S version 13
# (negotiated 0x0304 from supported_versions), ALPN 00, ext-count 02. The
# fingerprint varies ONLY by the echoed cipher suite.
#
# JA3S string = md5("771,<cipher_decimal>,43-51") where <cipher_decimal> is the
# LITERAL wire value of the suite (same rule the 1.2 path above uses: 0xc02f ->
# 49199). So 0x1301->4865, 0x1302->4866, 0x1303->4867.
#
# NOTE (plan correction): the plan's "Pinned oracle constants" table lists the
# JA3S strings for 0x1302/0x1303 as 771,4870,.. and 771,4871,.. — but 4870 is
# 0x1306 and 4871 is 0x1307, NOT the suites they're paired with. A real-wire
# ServerHello echoing 0x1302 yields the decimal 4866 (verified: 0x1302 == 4866).
# We assert the CORRECT, independently re-derived JA3S for the actual suite
# bytes (printf '771,4866,43-51'|md5sum -> 15af977c..). 0x1301 is consistent
# with the plan and is the primary discriminating fingerprint (LANDMINE #1).
# All JA4S goldens match the plan verbatim (the cipher field is lowercase hex,
# unaffected by the decimal transcription bug).

TLS13_LEGACY = 0x0303          # ServerHello legacy_version (1.3 on the wire)
# (suite_id, JA3S string, JA3S md5, JA4S)
TLS13_GOLDENS = [
    (0x1301, "771,4865,43-51", "f4febc55ea12b31ae17cfb7e614afda8", "t130200_1301_a56c5b993250"),
    (0x1302, "771,4866,43-51", "15af977ce25de452b96affa2addb1036", "t130200_1302_a56c5b993250"),
    (0x1303, "771,4867,43-51", "475c9302dc42b2751db9edcac3b74891", "t130200_1303_a56c5b993250"),
]

def _x25519_key_share():
    # key_share entry: group 0x001d (x25519), key_len 0x0020, 32-byte key.
    return struct.pack(">HH", 0x001d, 0x0020) + b"\x42" * 32

def _sh13_ext_block(key_share_body):
    # supported_versions (0x002b): single 2-byte version 0x0304 (NOT a list, on SH).
    sv = struct.pack(">H", 0x002b) + struct.pack(">H", 2) + struct.pack(">H", 0x0304)
    # key_share (0x0033): server entry (full) or group-only (HRR).
    ks = struct.pack(">H", 0x0033) + struct.pack(">H", len(key_share_body)) + key_share_body
    return sv + ks

def _sh13_body(suite, ext_block, sid=b""):
    b = struct.pack(">H", TLS13_LEGACY) + b"\x33" * 32          # version + random
    b += bytes([len(sid)]) + sid                               # session_id
    b += struct.pack(">H", suite) + b"\x00"                    # cipher + compression null
    b += struct.pack(">H", len(ext_block)) + ext_block         # extensions
    return b

def _sh13_record(suite, ext_block, sid=b""):
    body = _sh13_body(suite, ext_block, sid)
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body     # type=2 + 3-byte len
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs   # record: content=22, ver 0x0303

def _assert_tls13(res, suite, ja3s_string, ja3s_md5, ja4s):
    assert res["version"] == 771, res
    assert res["cipher"] == suite, res
    assert res["extensions"] == [0x002b, 0x0033], res
    assert res["ja3s_string"] == ja3s_string, res
    assert res["ja3s"] == ja3s_md5, res
    assert res["ja4s"] == ja4s, res

def test_tls13_serverhello():
    # Full ServerHello (real key_share entry) with a non-empty session_id, for
    # each of the 1.3 suites — assert JA3S string/md5 + JA4S vs pinned goldens.
    sid = b"\xab" * 32
    ks = _x25519_key_share()
    for suite, s, md5, ja4s in TLS13_GOLDENS:
        res = _run([_eth(_ip_tcp(_sh13_record(suite, _sh13_ext_block(ks), sid), 443, 50000, 1000))])
        _assert_tls13(res, suite, s, md5, ja4s)
    print("test_tls13_serverhello OK")

def test_tls13_hrr_shaped():
    # HelloRetryRequest-shaped SH: same two ext TYPES, key_share carries the
    # group ONLY (2-byte selected_group, no key). Fingerprints must be identical
    # — only ext types (not the key_share body) feed JA3S/JA4S.
    hrr_ks = struct.pack(">H", 0x001d)   # selected_group only
    for suite, s, md5, ja4s in TLS13_GOLDENS:
        res = _run([_eth(_ip_tcp(_sh13_record(suite, _sh13_ext_block(hrr_ks)), 443, 50000, 2000))])
        _assert_tls13(res, suite, s, md5, ja4s)
    print("test_tls13_hrr_shaped OK")

if __name__ == "__main__":
    test_single()
    test_two_connections()
    test_sll2()
    test_tls13_serverhello()
    test_tls13_hrr_shaped()
