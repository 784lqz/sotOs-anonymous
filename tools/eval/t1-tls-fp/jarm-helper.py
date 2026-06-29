#!/usr/bin/env python3
"""JARM Fingerprinting Helper (stub for T1 evaluation harness)"""
import socket, struct, hashlib, sys

def craft_clienthello(tls_version=0x0303, cipher_suites=None, curves=None):
    if cipher_suites is None:
        cipher_suites = [0x1301, 0x1302, 0x1303]
    if curves is None:
        curves = [0x001d, 0x0017, 0x0018]
    fixed_random = b'jarm_fixed_32_bytes_____seed_1234'[:32]
    ch = struct.pack('>H', tls_version) + fixed_random + b'\x00'
    cs_bytes = b''.join(struct.pack('>H', cs) for cs in cipher_suites)
    ch += struct.pack('>H', len(cs_bytes)) + cs_bytes + b'\x01\x00'
    exts = struct.pack('>HH', 0x002b, 4) + b'\x03\x03\x03\x04'
    grp_bytes = b''.join(struct.pack('>H', c) for c in curves)
    exts += struct.pack('>HH', 0x000a, len(grp_bytes) + 2) + struct.pack('>H', len(grp_bytes)) + grp_bytes
    ch += struct.pack('>H', len(exts)) + exts
    hs = struct.pack('>B', 0x01) + struct.pack('>I', len(ch))[1:] + ch
    return struct.pack('>B', 0x16) + struct.pack('>H', tls_version) + struct.pack('>H', len(hs)) + hs

def send_probe(host, port, clienthello):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((host, port))
        sock.sendall(clienthello)
        hdr = sock.recv(5)
        if len(hdr) < 5:
            return None
        rec_len = struct.unpack('>H', hdr[3:5])[0]
        body = b''
        while len(body) < rec_len:
            chunk = sock.recv(rec_len - len(body))
            if not chunk:
                break
            body += chunk
        sock.close()
        return hdr + body
    except:
        return None

def jarm_probe(host, port):
    probes = [
        {'suites': [0x1301, 0x1302, 0x1303], 'curves': [0x001d, 0x0017, 0x0018]},
        {'suites': [0x1301, 0x1302, 0x1303], 'curves': [0x0017, 0x0018]},
        {'suites': [0x1302, 0x1303, 0x1301], 'curves': [0x001d, 0x0017, 0x0018]},
        {'suites': [0x1303, 0x1301, 0x1302], 'curves': [0x001d, 0x0017]},
        {'suites': [0x1301, 0x1302, 0x1303], 'curves': [0x001d]},
        {'suites': [0x1301], 'curves': [0x001d, 0x0017, 0x0018]},
        {'suites': [0x1302, 0x1301], 'curves': [0x0017]},
        {'suites': [0x1303, 0x1302], 'curves': [0x0018]},
        {'suites': [0x1301], 'curves': [0x0017]},
        {'suites': [0x1302], 'curves': [0x0018]},
    ]
    results = []
    for cfg in probes:
        ch = craft_clienthello(cipher_suites=cfg['suites'], curves=cfg['curves'])
        resp = send_probe(host, port, ch)
        if resp and len(resp) > 9:
            results.append('ok')
        else:
            results.append('timeout')
    agg = ','.join(results)
    return f"jarm_{hashlib.sha256(agg.encode()).hexdigest()[:12]}"

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: jarm-helper.py <host:port>', file=sys.stderr)
        sys.exit(1)
    target = sys.argv[1]
    if ':' not in target:
        target += ':443'
    host, port = target.rsplit(':', 1)
    print(jarm_probe(host, int(port)))
