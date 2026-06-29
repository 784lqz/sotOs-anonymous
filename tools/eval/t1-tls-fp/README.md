# Experiment T1: TLS Fingerprints (JA3S / JA4S / JARM)

## Overview

T1 evaluates the **byte-for-byte equivalence** of sotOs TLS ServerHello responses to
a real nginx:alpine reference server, using three fingerprinting methods: JA3S, JA4S, JARM.

## Hypothesis

If sotOs ServerHello bytes are byte-for-byte identical to nginx:alpine, then all three
fingerprinting methods will yield identical hash values across a fixed 7-client set
and multiple runs.

## Fixed Client Set (7 clients)

| Client | TLS | Cipher Suite | Curve | Notes |
|--------|-----|--------------|-------|-------|
| client_1_tls13_default | 1.3 | default (0x1302 first) | default | OpenSSL's default cipher order |
| client_2_tls12 | 1.2 | ECDHE-RSA-AES128-GCM-SHA256 | N/A | TLS 1.2 fallback (mine2g/BearSSL) |
| client_3_tls13_p256 | 1.3 | AES-128-GCM-SHA256 | P-256 | secp256r1 (65B uncompressed point) |
| client_4_tls13_p384 | 1.3 | AES-128-GCM-SHA256 | P-384 | secp384r1 (97B uncompressed point) |
| client_5_tls13_reordered | 1.3 | 0x1301:0x1303:0x1302 | default | Reordered: 0x1301 first (tests client-order) |
| client_6_tls13_1302 | 1.3 | AES-256-GCM-SHA384 (0x1302) | default | Suite ε3 coverage |
| client_7_tls13_1303 | 1.3 | ChaCha20-Poly1305-SHA256 (0x1303) | default | Suite ε3 coverage + hand-rolled AEAD |

## Hostfwd Ports (from justfile:191)

- 18443 ← 443 (sotOs HTTPS)
- 18022 ← 22 (sotOs SSH)
- 18080 ← 80 (sotOs HTTP)

## TLS Responder Locations (code grounding)

- TLS 1.3 server: `src/net-synth/tls13.c` (ClientHello parse, suite selection, ServerHello serializers)
- AEAD: `src/net-synth/tls13_aead.c` (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
- Key schedule: `src/net-synth/tls13_keysched.c` (HKDF, key derivation)
- TLS 1.2 fallback: `src/net-synth/inbound_http.c` (mine2g/BearSSL dispatch)
- Pcap capture: `justfile:408` (filter-dump on net0)

## Reproducibility

```bash
cd /path/to/sotOs
just build  # Generates kernel, initrd, sotfs.img
bash tools/eval/t1-tls-fp/run.sh [RUNS=5]
```

## Pass Condition

- **Median match rate** = 1.0 (100%) for all 7 clients × 3 metrics (JA3S/JA4S/JARM)
- **p95 match rate** ≥ 0.8 (80%) — accounts for transient pcap loss

## References

- [JA3S Spec](https://github.com/salesforcecodedev/ja3)
- [JA4S Spec](https://github.com/FoxIO-LLC/ja4)
- [JARM Spec](https://github.com/salesforce/jarm)
