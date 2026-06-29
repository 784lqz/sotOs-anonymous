#!/usr/bin/env python3
"""Independent TLS 1.3 key-schedule oracle (RFC 8446 §7.1), pure stdlib.

Cross-checks src/net-synth/tls13_keysched.c against the SAME RFC 8448 §3 inputs.
Reproduces the RFC outputs => proves the ladder is implemented correctly (not a
mirror of the C). Doubles as a regression oracle.
"""
import hashlib, hmac

H = hashlib.sha256
HLEN = 32

def hkdf_extract(salt, ikm):
    if not salt:
        salt = b"\x00" * HLEN
    return hmac.new(salt, ikm, H).digest()

def hkdf_expand(prk, info, length):
    out, t, ctr = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([ctr]), H).digest()
        out += t; ctr += 1
    return out[:length]

def expand_label(secret, label, ctx, length):
    full = b"tls13 " + label.encode()
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return hkdf_expand(secret, info, length)

def derive_secret(secret, label, th):
    return expand_label(secret, label, th, HLEN)

def hexb(s):
    return bytes.fromhex(s.replace(" ", ""))

# RFC 8448 §3 inputs/goldens
ECDHE   = hexb("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
TH_CHSH = hexb("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
TH_FULL = hexb("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
G = {
 "c_hs_secret": "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
 "s_hs_secret": "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
 "c_hs_key":    "dbfaa693d1762c5b666af5d950258d01",
 "c_hs_iv":     "5bd3c71b836e0b76bb73265f",
 "s_hs_key":    "3fce516009c21727d0f2e4e86ee403bc",
 "s_hs_iv":     "5d313eb2671276ee13000b30",
 "master":      "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
 "c_ap_secret": "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
 "s_ap_secret": "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
 "s_ap_key":    "9f02283b6c9c07efc26bb9f2ac92e356",
 "s_ap_iv":     "cf782b88dd83549aadf1e984",
 "s_finished":  "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8",
 "c_finished":  "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4",
}

empty_th = H(b"").digest()
early   = hkdf_extract(None, b"\x00"*HLEN)
derived = derive_secret(early, "derived", empty_th)
hs      = hkdf_extract(derived, ECDHE)
c_hs    = derive_secret(hs, "c hs traffic", TH_CHSH)
s_hs    = derive_secret(hs, "s hs traffic", TH_CHSH)
c_hs_key= expand_label(c_hs, "key", b"", 16)
c_hs_iv = expand_label(c_hs, "iv",  b"", 12)
s_hs_key= expand_label(s_hs, "key", b"", 16)
s_hs_iv = expand_label(s_hs, "iv",  b"", 12)
s_fin   = expand_label(s_hs, "finished", b"", 32)
c_fin   = expand_label(c_hs, "finished", b"", 32)
derived2= derive_secret(hs, "derived", empty_th)
master  = hkdf_extract(derived2, b"\x00"*HLEN)
c_ap    = derive_secret(master, "c ap traffic", TH_FULL)
s_ap    = derive_secret(master, "s ap traffic", TH_FULL)
s_ap_key= expand_label(s_ap, "key", b"", 16)
s_ap_iv = expand_label(s_ap, "iv",  b"", 12)

checks = [
 ("c_hs_secret", c_hs), ("s_hs_secret", s_hs), ("c_hs_key", c_hs_key),
 ("c_hs_iv", c_hs_iv), ("s_hs_key", s_hs_key),
 ("s_hs_iv", s_hs_iv), ("master", master), ("s_finished", s_fin),
 ("c_finished", c_fin), ("c_ap_secret", c_ap), ("s_ap_secret", s_ap),
 ("s_ap_key", s_ap_key), ("s_ap_iv", s_ap_iv),
]
ok = True
for name, val in checks:
    want = G[name]
    got = val.hex()
    status = "OK" if got == want else "FAIL"
    if got != want: ok = False
    print(f"  {status:4} {name:12} {got}")
print("oracle reproduces RFC 8448 §3:", "PASS" if ok else "FAIL")

# ── ε2 task 7(c): P-384 key-schedule vector (48-byte IKM) ───────────────────
# Proves the keysched IKM-length change (tls13_hkdf_extract uses
# s->ecdhe_shared_len) is correct for P-384: the SAME RFC 8446 §7.1 ladder run
# with a 48-byte ECDHE shared secret (from oracle_ecdh.py's P384 SHARED) and a
# fixed, reproducible transcript hash.  The C test (test_schedule.c) pins these
# exact golden bytes and asserts tls13_key_schedule_handshake reproduces them
# when fed s.ecdhe_shared (48B) + s.ecdhe_shared_len==48.
P384_ECDHE = hexb(
    "40507e0769c6022e52cb96c95a0e7950e89d9a3e94ac482947fbcd8f17309dc7"
    "ca28cf6adc256f3b7a122ba20725191f")          # oracle_ecdh.py P384 SHARED (48B)
P384_TH_CHSH = hashlib.sha256(b"sotos-p384-th-chsh").digest()  # fixed, reproducible
p384_early   = hkdf_extract(None, b"\x00" * HLEN)
p384_derived = derive_secret(p384_early, "derived", empty_th)
p384_hs      = hkdf_extract(p384_derived, P384_ECDHE)          # 48B IKM here
p384_c_hs    = derive_secret(p384_hs, "c hs traffic", P384_TH_CHSH)
p384_s_hs    = derive_secret(p384_hs, "s hs traffic", P384_TH_CHSH)
p384_c_hs_key= expand_label(p384_c_hs, "key", b"", 16)
p384_c_hs_iv = expand_label(p384_c_hs, "iv",  b"", 12)
p384_s_hs_key= expand_label(p384_s_hs, "key", b"", 16)
p384_s_hs_iv = expand_label(p384_s_hs, "iv",  b"", 12)
p384_derived2= derive_secret(p384_hs, "derived", empty_th)
p384_master  = hkdf_extract(p384_derived2, b"\x00" * HLEN)
print("P-384 (48B IKM) key-schedule vector:")
print(f"  TH_CHSH      {P384_TH_CHSH.hex()}")
print(f"  c_hs_secret  {p384_c_hs.hex()}")
print(f"  s_hs_secret  {p384_s_hs.hex()}")
print(f"  c_hs_key     {p384_c_hs_key.hex()}")
print(f"  c_hs_iv      {p384_c_hs_iv.hex()}")
print(f"  s_hs_key     {p384_s_hs_key.hex()}")
print(f"  s_hs_iv      {p384_s_hs_iv.hex()}")
print(f"  master       {p384_master.hex()}")

# ── ε3 task A2: SHA-384 key-schedule vector (suite 0x1302) ───────────────────
# INDEPENDENT re-derivation of the RFC 8446 §7.1 ladder run with H=SHA-384 /
# HLEN=48 (NOT a mirror of the C — pure stdlib hmac/hashlib here).  This is the
# structural change 0x1302 (TLS_AES_256_GCM_SHA384) brings: every secret /
# finished value is 48B, key=32B, iv stays 12B.  Fixed, reproducible inputs that
# mirror the P-384 block above:
#   TH_CHSH = SHA-384("sotos-1302-th-chsh")   (48B transcript hash, fixed)
#   ECDHE   = the SAME fixed 48B P-384 shared secret reused from above
# The C test (test_schedule.c, suite 0x1302) pins these exact golden bytes and
# asserts tls13_key_schedule_handshake / _application reproduce them via SHA-384.
# Agreement between this independent ladder and the C proves the SHA-384 path.
def sha384_hkdf_extract(salt, ikm):
    if not salt:
        salt = b"\x00" * 48
    return hmac.new(salt, ikm, hashlib.sha384).digest()
def sha384_hkdf_expand(prk, info, length):
    out, t, ctr = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha384).digest()
        out += t; ctr += 1
    return out[:length]
def sha384_expand_label(secret, label, ctx, length):
    full = b"tls13 " + label.encode()
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return sha384_hkdf_expand(secret, info, length)
def sha384_derive_secret(secret, label, th):
    return sha384_expand_label(secret, label, th, 48)   # HLEN=48 for SHA-384

S384_ECDHE   = P384_ECDHE                                    # reuse the 48B P-384 shared
S384_TH_CHSH = hashlib.sha384(b"sotos-1302-th-chsh").digest()  # 48B, fixed
S384_TH_FULL = hashlib.sha384(b"sotos-1302-th-full").digest()  # 48B, fixed
s384_empty_th = hashlib.sha384(b"").digest()
s384_early    = sha384_hkdf_extract(None, b"\x00" * 48)
s384_derived  = sha384_derive_secret(s384_early, "derived", s384_empty_th)
s384_hs       = sha384_hkdf_extract(s384_derived, S384_ECDHE)
s384_c_hs     = sha384_derive_secret(s384_hs, "c hs traffic", S384_TH_CHSH)
s384_s_hs     = sha384_derive_secret(s384_hs, "s hs traffic", S384_TH_CHSH)
s384_c_hs_key = sha384_expand_label(s384_c_hs, "key", b"", 32)   # AES-256 → 32B key
s384_c_hs_iv  = sha384_expand_label(s384_c_hs, "iv",  b"", 12)
s384_s_hs_key = sha384_expand_label(s384_s_hs, "key", b"", 32)
s384_s_hs_iv  = sha384_expand_label(s384_s_hs, "iv",  b"", 12)
s384_c_fin    = sha384_expand_label(s384_c_hs, "finished", b"", 48)  # finished=48B
s384_s_fin    = sha384_expand_label(s384_s_hs, "finished", b"", 48)
s384_derived2 = sha384_derive_secret(s384_hs, "derived", s384_empty_th)
s384_master   = sha384_hkdf_extract(s384_derived2, b"\x00" * 48)
s384_c_ap     = sha384_derive_secret(s384_master, "c ap traffic", S384_TH_FULL)
s384_s_ap     = sha384_derive_secret(s384_master, "s ap traffic", S384_TH_FULL)
s384_c_ap_key = sha384_expand_label(s384_c_ap, "key", b"", 32)
s384_c_ap_iv  = sha384_expand_label(s384_c_ap, "iv",  b"", 12)
s384_s_ap_key = sha384_expand_label(s384_s_ap, "key", b"", 32)
s384_s_ap_iv  = sha384_expand_label(s384_s_ap, "iv",  b"", 12)
print("SHA-384 (suite 0x1302) key-schedule vector:")
print(f"  TH_CHSH      {S384_TH_CHSH.hex()}")
print(f"  TH_FULL      {S384_TH_FULL.hex()}")
print(f"  c_hs_secret  {s384_c_hs.hex()}")
print(f"  s_hs_secret  {s384_s_hs.hex()}")
print(f"  c_hs_key     {s384_c_hs_key.hex()}")
print(f"  c_hs_iv      {s384_c_hs_iv.hex()}")
print(f"  s_hs_key     {s384_s_hs_key.hex()}")
print(f"  s_hs_iv      {s384_s_hs_iv.hex()}")
print(f"  c_finished   {s384_c_fin.hex()}")
print(f"  s_finished   {s384_s_fin.hex()}")
print(f"  master       {s384_master.hex()}")
print(f"  c_ap_secret  {s384_c_ap.hex()}")
print(f"  s_ap_secret  {s384_s_ap.hex()}")
print(f"  c_ap_key     {s384_c_ap_key.hex()}")
print(f"  c_ap_iv      {s384_c_ap_iv.hex()}")
print(f"  s_ap_key     {s384_s_ap_key.hex()}")
print(f"  s_ap_iv      {s384_s_ap_iv.hex()}")

# ── ε3 task A2: RFC 4231 §4.5 HMAC-SHA-384 known-answer vector (Test Case 4) ──
# Anchors the br_sha384_vtable HMAC wiring independently of the schedule.  Key =
# 0x01..0x19 (25B), Data = 0xcd × 50.  Pinned from RFC 4231 §4.5 (authoritative).
# The C test (test_keysched.c) drives tls13_hkdf_extract(key, data) — which is
# HMAC(salt=key, ikm=data) — with the 0x1302 suite and asserts this exact mac.
RFC4231_TC4_KEY  = bytes(range(0x01, 0x1a))
RFC4231_TC4_DATA = b"\xcd" * 50
RFC4231_TC4_MAC  = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"
tc4 = hmac.new(RFC4231_TC4_KEY, RFC4231_TC4_DATA, hashlib.sha384).hexdigest()
print("RFC 4231 §4.5 HMAC-SHA-384 KAT:")
print(f"  key          {RFC4231_TC4_KEY.hex()}")
print(f"  data         {RFC4231_TC4_DATA.hex()}")
print(f"  mac          {tc4}")
print("HMAC-SHA-384 reproduces RFC 4231 §4.5:", "PASS" if tc4 == RFC4231_TC4_MAC else "FAIL")
if tc4 != RFC4231_TC4_MAC: ok = False

raise SystemExit(0 if ok else 1)
