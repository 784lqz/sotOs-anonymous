#!/usr/bin/env python3
"""Minimal SSH-2.0 client: version exchange + KEXINIT + curve25519-sha256 KEX,
then compute the exchange hash H and VERIFY the server's rsa-sha2-256 host-key
signature. Prints each field + H + the verdict. A reference to validate the
sotOs :22 honeypot against a real openssh sshd. Cleartext through KEX only.
Usage: ssh_probe.py <host> <port>"""
import sys, socket, struct, hashlib, os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

def u32(n): return struct.pack('>I', n)
def sstr(b): return u32(len(b)) + b
def nl(items): return sstr(b','.join(i.encode() for i in items))
def mpint(b):
    b = b.lstrip(b'\x00')
    if not b: return u32(0)
    if b[0] & 0x80: b = b'\x00' + b
    return u32(len(b)) + b

SEP = bool(os.environ.get('SEP'))   # force separate segments + delays (mimic real ssh)
class C:
    def __init__(s, host, port):
        s.s = socket.create_connection((host, port), timeout=10)
        s.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.buf = b''
    def recvline(s):
        while b'\n' not in s.buf:
            s.buf += s.s.recv(4096)
        line, s.buf = s.buf.split(b'\n', 1)
        return line.rstrip(b'\r')
    def need(s, n):
        while len(s.buf) < n:
            d = s.s.recv(4096)
            if not d: raise EOFError()
            s.buf += d
    def recv_pkt(s):
        s.need(4); plen = struct.unpack('>I', s.buf[:4])[0]
        s.need(4 + plen); pkt = s.buf[4:4+plen]; s.buf = s.buf[4+plen:]
        padlen = pkt[0]; return pkt[1:len(pkt)-padlen]   # payload
    def send_pkt(s, payload):
        plen = len(payload)
        pad = 8 - ((plen + 5) % 8)
        if pad < 4: pad += 8
        pkt = bytes([pad]) + payload + os.urandom(pad)
        s.s.sendall(u32(len(pkt)) + pkt)

def kexinit_payload(cookie):
    # optionally inflate the kex name-list to mimic OpenSSH's large (~1456B) KEXINIT
    kex = ['curve25519-sha256']
    if os.environ.get('BIGKEX'):
        kex += ['bogus-kex-%03d@example.org' % i for i in range(60)]  # ~1440B payload
    return (bytes([20]) + cookie
        + nl(kex) + nl(['rsa-sha2-256','rsa-sha2-512','ssh-rsa'])
        + nl(['aes128-ctr']) + nl(['aes128-ctr']) + nl(['hmac-sha2-256']) + nl(['hmac-sha2-256'])
        + nl(['none']) + nl(['none']) + sstr(b'') + sstr(b'') + bytes([0]) + u32(0))

def main():
    host, port = sys.argv[1], int(sys.argv[2])
    c = C(host, port)
    import time
    VC = (os.environ.get('VC') or 'SSH-2.0-sshprobe_1.0').encode()
    c.s.sendall(VC + b'\r\n')
    if SEP: time.sleep(0.3)        # separate the ID segment from KEXINIT (like real ssh)
    VS = c.recvline()
    print('V_S =', VS)
    IC = kexinit_payload(os.urandom(16))
    c.send_pkt(IC)
    if SEP: time.sleep(0.3)        # separate KEXINIT from KEX_ECDH_INIT
    # read packets until KEXINIT (server may send others)
    while True:
        p = c.recv_pkt()
        if p and p[0] == 20: IS = p; break
    # X25519
    priv = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    QC = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    c.send_pkt(bytes([30]) + sstr(QC))   # KEX_ECDH_INIT
    while True:
        p = c.recv_pkt()
        if p and p[0] == 31: rep = p; break
    o = 1
    def rd(b, o): n = struct.unpack_from('>I', b, o)[0]; return b[o+4:o+4+n], o+4+n
    KS, o = rd(rep, o); QS, o = rd(rep, o); SIGB, o = rd(rep, o)
    K = priv.exchange(X25519PublicKey.from_public_bytes(QS))
    H = hashlib.sha256(sstr(VC)+sstr(VS)+sstr(IC)+sstr(IS)+sstr(KS)+sstr(QC)+sstr(QS)+mpint(K)).digest()
    # parse K_S (ssh-rsa: e, n) + SIG (algname, sigbytes)
    o2 = 0; kalg, o2 = rd(KS, o2); e, o2 = rd(KS, o2); n, o2 = rd(KS, o2)
    o3 = 0; salg, o3 = rd(SIGB, o3); sig, o3 = rd(SIGB, o3)
    print('host-key alg =', kalg, ' sig alg =', salg, ' |sig|=', len(sig))
    print('H =', H.hex())
    pub = rsa.RSAPublicNumbers(int.from_bytes(e,'big'), int.from_bytes(n,'big')).public_key()
    def vok(h):
        try: pub.verify(sig, h, padding.PKCS1v15(), Prehashed(hashes.SHA256())); return True
        except Exception: return False
    # SSH signs H as a MESSAGE → RSASSA-PKCS1-v1.5 hashes it → digest = SHA256(H).
    try:
        pub.verify(sig, H, padding.PKCS1v15(), hashes.SHA256())
        print('SIGNATURE: VALID via SHA256(H)  <-- correct SSH semantics (sign SHA256(H), not H)')
        return
    except Exception: pass
    if vok(H):
        print('SIGNATURE: VALID via Prehashed(H)  <-- sotOs-style (signs H directly; WRONG for real SSH)')
    else:
        print('SIGNATURE: INVALID -> brute-forcing the H assembly against this real server...')
        base = sstr(VC)+sstr(VS)+sstr(IC)+sstr(IS)+sstr(KS)+sstr(QC)+sstr(QS)
        variants = {
            'mpint(K)': mpint(K), 'mpint(rev K)': mpint(K[::-1]),
            'sstr(K)': sstr(K), 'sstr(rev K)': sstr(K[::-1]), 'raw K': K, 'raw rev K': K[::-1],
        }
        found=False
        for klab, kf in variants.items():
            if vok(hashlib.sha256(base+kf).digest()): print('  *** K-variant MATCH:', klab); found=True
        if not found:
            # try I_C/I_S WITHOUT the leading msg byte
            base2 = sstr(VC)+sstr(VS)+sstr(IC[1:])+sstr(IS[1:])+sstr(KS)+sstr(QC)+sstr(QS)
            for klab, kf in variants.items():
                if vok(hashlib.sha256(base2+kf).digest()): print('  *** (IC/IS no-msgbyte) K-variant MATCH:', klab); found=True
        if not found: print('  no simple variant matched — dumping fields'); print('  K=',K.hex())

if __name__ == '__main__': main()
