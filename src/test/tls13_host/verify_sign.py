#!/usr/bin/env python3
# verify_sign.py — INDEPENDENT RSA-PSS verify of the C signer's CertificateVerify
# signature.  Reads hex lines from stdin.  The authority: if cryptography rejects,
# the C EMSA-PSS encoding is wrong (the ζ false-green trap — do NOT self-verify).
#
#   ε1 (sigalg 0x0804): rsa_pss_rsae_sha256, sLen=32, over a 130-byte content blob.
#     labels: N, E, CONTENT, SIG, SIGBAD
#   ε3 (sigalg 0x0805): rsa_pss_rsae_sha384, sLen=48, over a 146-byte content blob.
#     labels: N, E, CONTENT384, SIG384, SIGBAD384  (SHA-384, MGF1-SHA-384, salt=48)
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

LABELS = ("N", "E", "CONTENT", "SIG", "SIGBAD",
          "CONTENT384", "SIG384", "SIGBAD384")

vals = {}
for line in sys.stdin:
    parts = line.split()
    if len(parts) == 2 and parts[0] in LABELS:
        vals[parts[0]] = bytes.fromhex(parts[1])

for k in ("N", "E"):
    if k not in vals:
        print("MISSING %s" % k); sys.exit(1)

N = int.from_bytes(vals["N"], "big")
E = int.from_bytes(vals["E"], "big")
pub = rsa.RSAPublicNumbers(E, N).public_key()


def verify_block(tag, content_key, sig_key, sigbad_key, hash_alg, slen):
    """Verify one PSS signature + assert its tamper-flip is rejected."""
    for k in (content_key, sig_key, sigbad_key):
        if k not in vals:
            print("MISSING %s" % k); sys.exit(1)
    pss = padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=slen)
    try:
        pub.verify(vals[sig_key], vals[content_key], pss, hash_alg)
    except InvalidSignature:
        print("%s PSS VERIFY REJECTED" % tag); sys.exit(1)
    print("%s PSS VERIFY OK" % tag)
    try:
        pub.verify(vals[sigbad_key], vals[content_key], pss, hash_alg)
        print("%s TAMPER NOT REJECTED" % tag); sys.exit(1)
    except InvalidSignature:
        print("%s PSS TAMPER REJECTED OK" % tag)


# ε1: SHA-256 path (0x0804) — must stay green (regression).
verify_block("SHA256", "CONTENT", "SIG", "SIGBAD", hashes.SHA256(), 32)

# ε3: SHA-384 path (0x0805) — new.  146-byte blob, MGF1-SHA-384, salt=48.
verify_block("SHA384", "CONTENT384", "SIG384", "SIGBAD384", hashes.SHA384(), 48)
