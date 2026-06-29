#!/usr/bin/env python3
"""Independent ECDH ground-truth oracle for the TLS 1.3 ε2 key-share groups.

This is the AUTHORITY for the prime-curve ECDHE shared secret. The C path
(src/net-synth/tls13.c derive_ecdhe) uses BearSSL br_ec_prime_i31: mul()
yields a FULL uncompressed point 0x04||X||Y in-place, and the TLS 1.3 ECDHE
shared secret is ONLY the X-coordinate (32B for P-256, 48B for P-384). A wrong
offset/length there yields a wrong-but-nonzero secret that passes the all-zero
guard and fails ONLY at the client's Finished. So we pin the exact golden bytes
here, computed with an INDEPENDENT library (cryptography.hazmat ec), and a later
C test (task 4) must byte-match.

Two modes:
  - default / "vectors": print the FIXED-VECTOR golden (deterministic server
    scalars + a fixed client point) the C test pins, then SELF-CHECK.
  - "selfcheck": run only the self-check.

Self-check: for each curve we compute the shared secret TWO independent ways
(server_priv * client_pub  ==  client_priv * server_pub) via ECDH().exchange on
both sides and assert byte-equality. cryptography's exchange(ECDH()) already
returns the X-coordinate only, which is exactly the TLS 1.3 ECDHE secret, so the
golden is self-consistent and trustworthy without trusting our own arithmetic.
"""
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# --- curve registry --------------------------------------------------------
# tls13.h: TLS13_GROUP_SECP256R1 0x0017, TLS13_GROUP_SECP384R1 0x0018.
CURVES = {
    "P256": dict(curve=ec.SECP256R1(), coord=32, group=0x0017,
                 pub_len=65),   # 0x04 || X(32) || Y(32)
    "P384": dict(curve=ec.SECP384R1(), coord=48, group=0x0018,
                 pub_len=97),   # 0x04 || X(48) || Y(48)
}

# FIXED deterministic private scalars (big-endian). These are valid, in-range
# (less than the group order) for both curves, and reproducible. The C test
# feeds the SAME server scalar + the SAME client point and must reproduce the
# server public point and shared secret printed below.
#
# server scalar: 0x02 02 02 ... (coord_len bytes)  -- trivially in range
# client scalar: 0x03 03 03 ... (coord_len bytes)  -- trivially in range
SRV_SCALAR = {
    "P256": bytes([0x02]) * 32,
    "P384": bytes([0x02]) * 48,
}
CLI_SCALAR = {
    "P256": bytes([0x03]) * 32,
    "P384": bytes([0x03]) * 48,
}


def priv_from_scalar(curve, scalar_be):
    """Build an EC private key from a fixed big-endian scalar."""
    d = int.from_bytes(scalar_be, "big")
    return ec.derive_private_key(d, curve)


def uncompressed_pub(privkey):
    """0x04 || X || Y of the public point."""
    return privkey.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)


def pub_from_uncompressed(curve, point):
    """Parse a 0x04||X||Y client point into an EC public key."""
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, point)


def x_coord_of_point(point, coord):
    """Extract the X-coordinate (== the TLS 1.3 ECDHE secret) from 0x04||X||Y."""
    assert len(point) == 1 + 2 * coord, "bad uncompressed point length"
    assert point[0] == 0x04, "expected uncompressed point lead 0x04"
    return point[1:1 + coord]


def ecdh_secret(name, srv_scalar, cli_point):
    """Given a server scalar (be hex bytes) and a CLIENT uncompressed point,
    return (server_uncompressed_pub, shared_secret_x_only).

    The shared secret is the X-coordinate of (srv_scalar * client_point), which
    is exactly what cryptography's ECDH().exchange returns."""
    spec = CURVES[name]
    curve, coord = spec["curve"], spec["coord"]
    srv_priv = priv_from_scalar(curve, srv_scalar)
    cli_pub = pub_from_uncompressed(curve, cli_point)
    srv_pub = uncompressed_pub(srv_priv)
    shared = srv_priv.exchange(ec.ECDH(), cli_pub)   # X-coordinate only
    assert len(shared) == coord, "shared secret length mismatch"
    return srv_pub, shared


def self_check():
    """For each curve, compute the shared secret two independent ways and
    assert byte-equality:  srv_priv * cli_pub  ==  cli_priv * srv_pub.
    Both via ECDH().exchange (X-coord only), so this validates the golden
    against the curve math without trusting any of our own arithmetic."""
    ok = True
    for name in ("P256", "P384"):
        spec = CURVES[name]
        curve, coord = spec["curve"], spec["coord"]

        srv_priv = priv_from_scalar(curve, SRV_SCALAR[name])
        cli_priv = priv_from_scalar(curve, CLI_SCALAR[name])

        srv_pub_pt = uncompressed_pub(srv_priv)
        cli_pub_pt = uncompressed_pub(cli_priv)

        # Way 1: server side does srv_priv * client_public.
        sec_srv = srv_priv.exchange(ec.ECDH(), cli_priv.public_key())
        # Way 2: client side does cli_priv * server_public.
        sec_cli = cli_priv.exchange(ec.ECDH(), srv_priv.public_key())

        # The two ECDH directions MUST agree.
        eq = (sec_srv == sec_cli)

        # And our top-level ecdh_secret() (used to print the golden) must
        # reproduce the same server pub + secret from the same inputs.
        srv_pub2, shared2 = ecdh_secret(name, SRV_SCALAR[name], cli_pub_pt)
        consistent = (srv_pub2 == srv_pub_pt) and (shared2 == sec_srv)

        # Cross-validate that exchange()'s output equals the X-coord of the
        # full uncompressed shared point computed by hand (offset 1, len coord).
        # Derive the full shared point: cli_pub scaled by srv scalar.
        # cryptography does not expose the full point directly, but we can
        # confirm exchange() returns exactly `coord` bytes (the X-coord).
        len_ok = (len(sec_srv) == coord)

        passed = eq and consistent and len_ok
        ok = ok and passed
        print(f"  {name}: ecdh-both-sides-equal={eq} "
              f"golden-consistent={consistent} xcoord-len={coord}B "
              f"-> {'OK' if passed else 'FAIL'}")
    return ok


def print_vectors():
    """Emit the fixed-vector golden lines the C test pins."""
    for name in ("P256", "P384"):
        cli_priv = priv_from_scalar(CURVES[name]["curve"], CLI_SCALAR[name])
        cli_point = uncompressed_pub(cli_priv)
        srv_pub, shared = ecdh_secret(name, SRV_SCALAR[name], cli_point)

        # Inputs (so the C test can feed exactly these).
        print(f"{name} SRV_SCALAR {SRV_SCALAR[name].hex()}")
        print(f"{name} CLI_PUB    {cli_point.hex()}")
        # Outputs (the golden the C test must reproduce).
        print(f"{name} SRV_PUB {srv_pub.hex()}")
        print(f"{name} SHARED {shared.hex()}")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "vectors"
    if mode == "selfcheck":
        ok = self_check()
        print("ORACLE SELF-CHECK OK" if ok else "ORACLE SELF-CHECK FAIL")
        raise SystemExit(0 if ok else 1)

    # vectors mode (default): print golden, then self-check.
    print_vectors()
    ok = self_check()
    print("ORACLE SELF-CHECK OK" if ok else "ORACLE SELF-CHECK FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
