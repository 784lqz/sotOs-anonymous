#!/usr/bin/env python3
"""JA3S parser — extract the server-side TLS fingerprint from a pcap.

JA3S = md5("SSLVersion,Cipher,Extensions") where the fields come from the
ServerHello: legacy_version (decimal), the single selected cipher suite
(decimal), and the '-'-joined decimal list of extension types in order.
Stdlib only (struct/hashlib) — no scapy/tshark dependency.
"""
import os, struct, hashlib, sys, json

def _l2_strip(frame, linktype):
    """Return the IPv4 payload of an Ethernet/SLL/SLL2 frame, or None."""
    if linktype == 1:           # EN10MB
        if len(frame) < 14 or frame[12:14] != b"\x08\x00":
            return None
        return frame[14:]
    if linktype == 113:         # LINUX_SLL (tcpdump -i any, libpcap < 1.10)
        if len(frame) < 16 or frame[14:16] != b"\x08\x00":
            return None
        return frame[16:]
    if linktype == 276:         # LINUX_SLL2 (tcpdump -i any, libpcap >= 1.10)
        # SLL2: 2B protocol type, 2B reserved, 4B ifindex, 2B ARPHRD,
        # 1B pkt type, 1B addr len, 8B addr = 20B header; protocol at offset 0.
        if len(frame) < 20 or frame[0:2] != b"\x08\x00":
            return None
        return frame[20:]
    return None

def _server_streams(data):
    """Reassemble the byte stream from the server (src port == JA3S_SERVER_PORT),
    grouped per TCP connection (4-tuple), returned in first-seen order so a pcap
    with multiple server flows stays deterministic and never cross-corrupts."""
    server_port = int(os.environ.get("JA3S_SERVER_PORT", "443"))
    magic = data[:4]
    le = magic == b"\xd4\xc3\xb2\xa1"
    if not le and magic != b"\xa1\xb2\xc3\xd4":
        raise ValueError("not a libpcap file (bad magic %r)" % magic)
    end = "<" if le else ">"
    linktype = struct.unpack(end + "I", data[20:24])[0]
    conns = {}        # 4-tuple -> {seq: payload}
    order = []        # 4-tuples in first-seen order
    off = 24
    while off + 16 <= len(data):
        _, _, incl, _orig = struct.unpack(end + "IIII", data[off:off+16])
        off += 16
        frame = data[off:off+incl]
        off += incl
        ip = _l2_strip(frame, linktype)
        if not ip or len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0f) * 4
        if ip[9] != 6:                      # not TCP
            continue
        src_ip, dst_ip = ip[12:16], ip[16:20]
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        src_port = struct.unpack(">H", tcp[0:2])[0]
        dst_port = struct.unpack(">H", tcp[2:4])[0]
        if src_port != server_port:
            continue
        key = (src_ip, src_port, dst_ip, dst_port)
        seq = struct.unpack(">I", tcp[4:8])[0]
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if not payload:
            continue
        if key not in conns:
            conns[key] = {}
            order.append(key)
        conns[key].setdefault(seq, payload)
    streams = []
    for key in order:
        segs = conns[key]
        out = bytearray()
        for seq in sorted(segs):
            out += segs[seq]
        streams.append(bytes(out))
    return streams

def _parse_server_hello(stream):
    """Walk TLS records; return (version, cipher, [ext_types], neg_version) of the
    ServerHello. neg_version is the supported_versions (0x002b) value if present
    (single 2-byte version on a ServerHello, NOT a list) else None — used for the
    JA4S negotiated-version field; legacy `version` is what JA3S uses."""
    i = 0
    while i + 5 <= len(stream):
        ctype = stream[i]
        rec_len = struct.unpack(">H", stream[i+3:i+5])[0]
        body = stream[i+5:i+5+rec_len]
        i += 5 + rec_len
        if ctype != 22:                     # handshake
            continue
        j = 0
        while j + 4 <= len(body):
            hs_type = body[j]
            hs_len = struct.unpack(">I", b"\x00" + body[j+1:j+4])[0]
            hs = body[j+4:j+4+hs_len]
            j += 4 + hs_len
            if hs_type != 2:                # ServerHello
                continue
            version = struct.unpack(">H", hs[0:2])[0]
            k = 2 + 32                       # version + random
            sid_len = hs[k]; k += 1 + sid_len
            cipher = struct.unpack(">H", hs[k:k+2])[0]; k += 2
            k += 1                           # compression method
            exts = []
            neg_version = None
            if k + 2 <= len(hs):
                ext_total = struct.unpack(">H", hs[k:k+2])[0]; k += 2
                stop = k + ext_total
                while k + 4 <= min(stop, len(hs)):
                    et = struct.unpack(">H", hs[k:k+2])[0]
                    el = struct.unpack(">H", hs[k+2:k+4])[0]
                    exts.append(et)
                    if et == 0x002b and el >= 2:        # supported_versions
                        neg_version = struct.unpack(">H", hs[k+4:k+6])[0]
                    k += 4 + el
            return version, cipher, exts, neg_version
    return None   # no ServerHello in this stream

def _ja4s_version(neg_version, legacy_version):
    """JA4S 2-char version. Prefer the negotiated supported_versions value
    (0x0304 -> '13'); else fall back to the legacy ServerHello version."""
    table = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}
    v = neg_version if neg_version is not None else legacy_version
    return table.get(v, "00")

def ja4s(cipher, exts, neg_version, legacy_version):
    """JA4S server fingerprint: t<ver><extcount><alpn>_<cipher>_<exthash>.

    Server path: extensions are taken in WIRE ORDER (no sort, no GREASE strip,
    unlike the JA4 client fingerprint). ALPN is '00' (a 1.3 ServerHello carries
    none). ext_hash = first 12 hex of sha256 over the comma-joined, lowercase
    4-hex ext types; '000000000000' when there are no extensions. Only the ext
    *types* feed the hash — the key_share body never leaks in."""
    version = _ja4s_version(neg_version, legacy_version)
    ext_count = "%02d" % min(len(exts), 99)
    alpn = "00"
    cipher_hex = "%04x" % cipher
    if exts:
        joined = ",".join("%04x" % e for e in exts)
        ext_hash = hashlib.sha256(joined.encode()).hexdigest()[:12]
    else:
        ext_hash = "000000000000"
    return "t%s%s%s_%s_%s" % (version, ext_count, alpn, cipher_hex, ext_hash)

def ja3s(path):
    with open(path, "rb") as f:
        data = f.read()
    for stream in _server_streams(data):
        parsed = _parse_server_hello(stream)
        if parsed is None:
            continue
        version, cipher, exts, neg_version = parsed
        s = "%d,%d,%s" % (version, cipher, "-".join(str(e) for e in exts))
        return {
            "version": version,
            "cipher": cipher,
            "extensions": exts,
            "ja3s_string": s,
            "ja3s": hashlib.md5(s.encode()).hexdigest(),
            "ja4s": ja4s(cipher, exts, neg_version, version),
        }
    raise ValueError("no ServerHello found in any server stream")

def main(argv):
    as_json = "--json" in argv
    only_ja4s = "--ja4s" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not args:
        print("usage: ja3s.py [--json] [--ja4s] <capture.pcap>", file=sys.stderr)
        return 2
    res = ja3s(args[0])
    if as_json:
        print(json.dumps(res))
    elif only_ja4s:
        print(res["ja4s"])
    else:
        print("JA3S       = %s" % res["ja3s"])
        print("JA3S string= %s" % res["ja3s_string"])
        print("JA4S       = %s" % res["ja4s"])
        print("version    = 0x%04x (%d)" % (res["version"], res["version"]))
        print("cipher     = 0x%04x" % res["cipher"])
        print("extensions = %s" % " ".join("0x%04x" % e for e in res["extensions"]))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
