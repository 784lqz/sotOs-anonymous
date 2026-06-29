#!/usr/bin/env python3
"""sotOs · HASSH oracle — read a server's SSH_MSG_KEXINIT, print the exact
ordered algorithm name-lists and compute HASSHServer (md5 of
kex;ciphers_s2c;macs_s2c;compression_s2c).  Used to capture the OpenSSH 9.7
ground truth and to verify the sotOs SSH server matches it byte-for-byte.

  tools/hassh.py <host> <port>
"""
import socket, sys, struct, hashlib

def recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise EOFError("short read")
        b += c
    return b

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    s = socket.create_connection((host, port), timeout=10)
    # banner exchange: read server banner line(s), send ours
    buf = b""
    while b"\r\n" not in buf:
        buf += s.recv(256)
    banner = buf.split(b"\r\n")[0].decode("latin1")
    s.sendall(b"SSH-2.0-hasshprobe\r\n")
    # any bytes after the banner CRLF are the start of the first binary packet
    rest = buf.split(b"\r\n", 1)[1]
    def feed(n):
        nonlocal rest
        while len(rest) < n:
            rest += s.recv(4096)
        out, rest = rest[:n], rest[n:]
        return out
    # binary packet: uint32 len, byte pad_len, payload, padding
    plen = struct.unpack(">I", feed(4))[0]
    pad = feed(1)[0]
    payload = feed(plen - 1)
    payload = payload[:plen - 1 - pad]
    msg = payload[0]
    if msg != 20:
        print(f"first packet is msg {msg}, not KEXINIT(20)"); sys.exit(2)
    p = 17  # skip msg byte (1) + cookie (16)
    names = []
    for _ in range(10):  # 10 name-lists
        ln = struct.unpack(">I", payload[p:p+4])[0]; p += 4
        names.append(payload[p:p+ln].decode("latin1")); p += ln
    kex, hostkey, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c, _, _ = names
    hassh_str = ";".join([kex, enc_s2c, mac_s2c, comp_s2c])
    hassh = hashlib.md5(hassh_str.encode()).hexdigest()
    print(f"banner       : {banner}")
    print(f"kex          : {kex}")
    print(f"hostkey      : {hostkey}")
    print(f"enc_s2c      : {enc_s2c}")
    print(f"mac_s2c      : {mac_s2c}")
    print(f"comp_s2c     : {comp_s2c}")
    print(f"HASSHServer  : {hassh}")
    s.close()

if __name__ == "__main__":
    main()
