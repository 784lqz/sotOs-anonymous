#!/usr/bin/env python3
"""Independent AEAD ground-truth oracle for the TLS 1.3 record layer (ε3).

This is the AUTHORITY for the sealed-record bytes the C path
(src/net-synth/tls13_aead.c tls13_record_seal/open) must reproduce. The C
path dispatches on suite->aead and feeds suite->key_len into BearSSL's
br_aes_ct64_ctr_init; a silent key truncation (using 16 bytes for an AES-256
suite) yields a wrong-but-plausible ciphertext that the *server* never notices
and that fails only at the client. So we pin the exact golden bytes here,
computed with an INDEPENDENT library (cryptography.hazmat AESGCM), and the C
test must byte-match.

Two anchors guarantee correctness without trusting our own arithmetic:

  1. A NIST CAVP AES-256 GCM Known-Answer-Test vector (96-bit IV, 16-byte tag)
     verified against cryptography.hazmat AESGCM in --selfcheck — this anchors
     the *bare* AES-256-GCM primitive (br_gcm over AES-256) independently of any
     TLS framing.

  2. The TLS-1.3-framed golden records (--cipher aes128 / aes256), produced by
     applying RFC 8446 §5.2/§5.3 framing (nonce = iv XOR (00..00||be64(seq)),
     5-byte AAD 17 03 03 || u16(ct_len), inner = pt || inner_type, ct = inner+tag)
     on top of cryptography's AESGCM.  These are exactly what tls13_record_seal
     emits; the C test pins them by byte-equality.

Modes:
  --selfcheck            : run the NIST KAT self-check only (exit 0/1)
  --cipher {aes128,aes256} (default aes256): print the TLS-framed golden lines
  --nist                 : print the bare NIST CAVP GCM-256 KAT line
(default with no args: print aes256 framed golden + the NIST KAT + self-check)
"""
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


# ── NIST CAVP AES-256 GCM KAT (gcmEncryptExtIV256.rsp, 96-bit IV / 128-bit tag).
# A canonical published vector (Keylen=256, IVlen=96, AADlen=128, Taglen=128).
# Source: NIST CAVP GCM test vectors (gcmEncryptExtIV256.rsp).
NIST = dict(
    key=bytes.fromhex("92e11dcdaa866f5ce790fd24501f9250"
                      "9aacf4cb8b1339d50c9c1240935dd08b"),
    iv=bytes.fromhex("ac93a1a6145299bde902f21a"),
    aad=bytes.fromhex("1e0889016f67601c8ebea4943bc23ad6"),
    pt=bytes.fromhex("2d71bcfa914e4ac045b2aa60955fad24"),
    ct=bytes.fromhex("8995ae2e6df3dbf96fac7b7137bae67f"),
    tag=bytes.fromhex("eca5aa77d51d4a0a14d9c51e1da474ab"),
)


def nist_selfcheck():
    """Verify the pinned NIST KAT against cryptography's AESGCM (independent)."""
    g = AESGCM(NIST["key"])
    out = g.encrypt(NIST["iv"], NIST["pt"], NIST["aad"])
    exp = NIST["ct"] + NIST["tag"]
    ok = (out == exp)
    # And the inverse: decrypt the KAT ciphertext+tag back to the plaintext.
    dec = g.decrypt(NIST["iv"], NIST["ct"] + NIST["tag"], NIST["aad"])
    ok = ok and (dec == NIST["pt"])
    print(f"  NIST CAVP GCM-256 KAT: encrypt-match={out == exp} "
          f"decrypt-match={dec == NIST['pt']} -> {'OK' if ok else 'FAIL'}")
    return ok


# ── RFC 7539 §2.8.2 canonical AEAD_CHACHA20_POLY1305 vector.
# The gold-standard published vector for ChaCha20-Poly1305: it pins the bare
# primitive (key/nonce/aad/pt -> ct/tag) before any TLS framing, removing the
# oracle-self-agreement risk.  Source: RFC 7539 §2.8.2.
RFC7539 = dict(
    key=bytes.fromhex("808182838485868788898a8b8c8d8e8f"
                      "909192939495969798999a9b9c9d9e9f"),
    iv=bytes.fromhex("070000004041424344454647"),
    aad=bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
    pt=(b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."),
    ct=bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"),
    tag=bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691"),
)


def rfc7539_selfcheck():
    """Verify the pinned RFC 7539 ChaCha20-Poly1305 vector via cryptography."""
    g = ChaCha20Poly1305(RFC7539["key"])
    out = g.encrypt(RFC7539["iv"], RFC7539["pt"], RFC7539["aad"])
    exp = RFC7539["ct"] + RFC7539["tag"]
    ok = (out == exp)
    dec = g.decrypt(RFC7539["iv"], RFC7539["ct"] + RFC7539["tag"], RFC7539["aad"])
    ok = ok and (dec == RFC7539["pt"])
    print(f"  RFC 7539 §2.8.2 ChaCha20-Poly1305 vector: encrypt-match={out == exp} "
          f"decrypt-match={dec == RFC7539['pt']} -> {'OK' if ok else 'FAIL'}")
    return ok


def mk_nonce(iv, seq):
    """RFC 8446 §5.3 record nonce: static_iv XOR (00..00 || be64(seq))."""
    s = (b"\x00" * 4) + seq.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, s))


def _aead(cipher, key):
    """Return the AEAD primitive for the named cipher (independent library)."""
    if cipher == "chacha20":
        return ChaCha20Poly1305(key)
    return AESGCM(key)


def seal(key, iv, seq, inner_type, pt, cipher="aes256"):
    """Produce one full TLS 1.3 ciphertext record (RFC 8446 §5.2).

    inner_plaintext = pt || inner_type (ε: zero padding).
    ct_len = len(inner) + 16 (tag).  AAD = 17 03 03 || u16(ct_len).
    record = 17 03 03 || u16(ct_len) || ciphertext || tag.

    cipher selects AES-GCM (aes128/aes256) or ChaCha20-Poly1305 (chacha20);
    both share the identical TLS-1.3 framing (nonce/AAD/tag layout).
    """
    inner = pt + bytes([inner_type])
    ct_len = len(inner) + 16
    aad = bytes([0x17, 0x03, 0x03]) + ct_len.to_bytes(2, "big")
    g = _aead(cipher, key)
    ct_and_tag = g.encrypt(mk_nonce(iv, seq), inner, aad)
    return aad + ct_and_tag


# Fixed framed-golden inputs.  Mirrors the existing aes128 inline goldens so the
# regression row is reproduced and the aes256 row is the new pin.
KEY16 = bytes(range(16))
KEY32 = bytes(range(32))
IV12 = bytes(range(12))

# Each tuple: (seq, inner_type, plaintext) — same vectors for both ciphers.
VECTORS = [
    (0, 0x16, b"hello"),
    (1, 0x17, b"world"),
]


def print_framed(cipher):
    key = KEY16 if cipher == "aes128" else KEY32   # aes256/chacha20 both use KEY32
    print(f"{cipher} KEY {key.hex()}")
    print(f"{cipher} IV  {IV12.hex()}")
    for seq, it, pt in VECTORS:
        rec = seal(key, IV12, seq, it, pt, cipher=cipher)
        print(f"{cipher} REC seq={seq} it={it:#04x} pt={pt.decode()} {rec.hex()}")


def print_rfc7539():
    print(f"RFC7539 KEY {RFC7539['key'].hex()}")
    print(f"RFC7539 IV  {RFC7539['iv'].hex()}")
    print(f"RFC7539 AAD {RFC7539['aad'].hex()}")
    print(f"RFC7539 PT  {RFC7539['pt'].hex()}")
    print(f"RFC7539 CT  {RFC7539['ct'].hex()}")
    print(f"RFC7539 TAG {RFC7539['tag'].hex()}")


def print_nist():
    print(f"NIST KEY {NIST['key'].hex()}")
    print(f"NIST IV  {NIST['iv'].hex()}")
    print(f"NIST AAD {NIST['aad'].hex()}")
    print(f"NIST PT  {NIST['pt'].hex()}")
    print(f"NIST CT  {NIST['ct'].hex()}")
    print(f"NIST TAG {NIST['tag'].hex()}")


def main():
    args = sys.argv[1:]
    if "--selfcheck" in args:
        # Anchor both bare primitives: NIST CAVP GCM-256 + RFC 7539 §2.8.2 ChaCha.
        ok = nist_selfcheck()
        ok = rfc7539_selfcheck() and ok
        print("ORACLE SELF-CHECK OK" if ok else "ORACLE SELF-CHECK FAIL")
        raise SystemExit(0 if ok else 1)

    cipher = "aes256"
    for a in args:
        if a == "--cipher":
            continue
        if a in ("aes128", "aes256", "chacha20"):
            cipher = a
    if "--cipher" in args:
        i = args.index("--cipher")
        if i + 1 < len(args):
            cipher = args[i + 1]

    if "--nist" in args:
        print_nist()
        ok = nist_selfcheck()
        print("ORACLE SELF-CHECK OK" if ok else "ORACLE SELF-CHECK FAIL")
        raise SystemExit(0 if ok else 1)

    if "--rfc7539" in args:
        print_rfc7539()
        ok = rfc7539_selfcheck()
        print("ORACLE SELF-CHECK OK" if ok else "ORACLE SELF-CHECK FAIL")
        raise SystemExit(0 if ok else 1)

    # default: print the requested framed golden + bare-primitive KATs + check.
    print_framed(cipher)
    print_nist()
    print_rfc7539()
    ok = nist_selfcheck()
    ok = rfc7539_selfcheck() and ok
    print("ORACLE SELF-CHECK OK" if ok else "ORACLE SELF-CHECK FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
