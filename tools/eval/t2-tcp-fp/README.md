# Experiment T2: TCP/IP Stack Fingerprinting

## Goal
Verify that active (nmap -O) and passive (p0f) OS fingerprints cannot distinguish sotOs from real Alpine 3.20.x.

## Protocol Overview

The evaluation has four phases:

### Phase 1: Reference Setup
- Identify a real Alpine 3.20.x host on the same network path (same hypervisor/virtio, same hop count).
- This is the control; sotOs must match it.

### Phase 2: Active Fingerprinting (nmap -O)
- Run `nmap -O --osscan-guess` against **both** sotOs and Alpine reference, n≥10 times.
- Extract raw fingerprint blocks (TCP probe responses T1-T7, UDP probe U1).
- Compute per-field differences: TTL, IP-ID (TI/II/TS classes), DF, Window, MSS, Wscale, option layout.

### Phase 3: Passive Fingerprinting (p0f)
- Sniff incoming TCP SYN from a real client to **both** hosts.
- Extract p0f signature (SYN flags, option layout, TTL) and OS inference.
- Both should yield Alpine / generic Linux, not a distinct fingerprint.

### Phase 4: Analysis & Reporting
- Compare fields field-by-field; compute "matched/total" ratio.
- Generate a CSV with per-probe results.
- Emit IEEE-style table for the paper.

## Design Rationale

### Why Control on Same Network Path?
**Critical control**: sotOs and Alpine must see the identical network hop-count, MTU, latency profile, and routing. If the reference is on a different WAN or has different TCP timing, differences are confounded with network position, not host behavior.

### Why n≥10 Iterations?
nmap OS detection has stochastic probe delivery (packet loss, timeouts). Statistical spread over 10+ rounds reveals confidence and variance. Report central tendency + dispersion (median/p95 or mean ± CI).

### Why Both Active & Passive?
- **Active**: nmap actively probes with specific flag combos (SYN, FIN, ACK-only, etc.) to trigger OS-specific behavior.
- **Passive**: p0f observes a real client's SYN and infers the server OS from response fingerprint alone.
Together they cover the attacker's full reconnaissance arsenal.

## sotOs Fingerprinting Specifics

From `src/sotnet/tcp.c` and `tcp_fp.c`:

### IP-Layer Fingerprint (RFC 791, RFC 9293)
- **TTL**: Fixed at 64 (SOTFP_TTL, tcp_fp.h:27)
- **IP-ID (SYN-ACK)**: Forced to 0 (tcp.c:228, `sotfp_ip_set(ip, (flags & TCP_FLAG_SYN) ? 0 : sotfp_next_ip_id(), 1)`)
- **IP-ID (ICMP/UDP)**: Incrementing via global counter `sotfp_next_ip_id()` (tcp_fp.c:6–8)
- **DF Bit**: Always set (df_set=1, tcp.c:228, 318)

### TCP-Layer Fingerprint
- **SYN-ACK Option Layout**: Hardcoded LINUX_SYNACK_OPTS (12 bytes):
  ```
  MSS=1460 (0x02,0x04,0x05,0xb4)
  NOP NOP (0x01,0x01)
  SACK-permitted (0x04,0x02)
  NOP (0x01)
  Window-Scale=10 (0x03,0x03,0x0a)
  ```
  From tcp.c:53–59. No EOL terminator (correct for TS-off Linux).

- **SYN-ACK Window**: Fixed at 64240 (LINUX_SYNACK_WINDOW, tcp.c:60)
  This is a p0f/nmap fingerprint tell; pinned to match real Linux.

- **SYN-ACK Flags**: SYN | ACK, plus ECE iff inbound SYN requests ECN (tcp_fp.c:53–59)

- **RST IP-ID**: Always 0 (tcp.c:318)

- **Data Segment IP-ID**: Incrementing (tcp.c:228)

## hostfwd Ports

From justfile:114, 145, 191, 435:
```
hostfwd=tcp::18022-:22      (SSH)
hostfwd=tcp::18080-:80      (HTTP)
hostfwd=tcp::18443-:443     (HTTPS)
```

sotOs runs via `just run-4pane` or similar. The guest's :22 is forwarded to host :18022.

**For nmap**: Target `127.0.0.1` (or the QEMU host IP) on these forwarded ports.

## Expected Results

### Field Concordance Matrix

| Field | Alpine Real | sotOs | Notes |
|-------|------------|-------|-------|
| TTL | 64 | 64 | ✓ Match |
| IP-ID (SYN-ACK) | Varies (class I) | 0 | Deliberate delta (see spec) |
| IP-ID (ICMP) | Incrementing | Incrementing | ✓ Match (class II) |
| DF (SYN-ACK) | 1 | 1 | ✓ Match |
| Window (SYN-ACK) | ~65535 (typical) | 64240 (pinned) | p0f-discoverable delta; acceptable |
| MSS | 1460 | 1460 | ✓ Match |
| Wscale | 10 | 10 | ✓ Match (RFC 7323 max clipped to 14) |
| Option Layout | mss,nop,nop,sackperm,nop,ws | mss,nop,nop,sackperm,nop,ws | ✓ Match |
| ECN Capable | If enabled | If inbound SYN says ECE+CWR | ✓ Match logic |

### Pass Condition

**Metric**: `Matched Fields / Total Fields`

- **Target**: ≥80% field concordance (allow 1–2 delta fields due to intentional FP spoofing)
- **nmap OS Verdict**: Should be "Alpine Linux" or generic "Linux" (not Cisco, Windows, BSD, etc.)
- **p0f OS Label**: Should be Alpine or Linux (not a distinct signature)
- **Confidence**: nmap average confidence ≥70% across n=10 rounds

### Known Deltas (Acceptable)

1. **IP-ID (SYN-ACK) = 0**: sotOs hardcodes this; real Alpine may vary. This is an **intentional spoofing technique** and acceptable.
2. **Window Size**: sotOs pins at 64240; real Alpine ≈65535. nmap/p0f may flag this, but it's within the range of OS variance.
3. **Option Ordering**: Minor variations in NOP placement; p0f's "layout" is string-matched, so exact match required.

## Existing Infrastructure Reuse

The codebase already has TCP fingerprinting helpers:

1. **tools/tcpfp.py**: Parses pcap for SYN-ACK fingerprints (sig, sig_os, TTL, DF, IP-ID, wscale, option layout).
   - Usage: `TCPFP_SERVER_PORT=443 tcpfp.py <capture.pcap> [--json]`

2. **tools/ipfp.py**: Parses pcap for ICMP-reply and RST (IP-ID, DF, TTL, flags).
   - Usage: `ipfp.py <pcap> [--rst-sport N | --tcp-ipids N]`

3. **Existing gates** (tools/*-gate.sh): Pattern for boot-driven headless measurement + log capture.

## Running the Evaluation

### Prerequisites
```bash
sudo apt install nmap p0f python3
# sotOs must be built:
just build
```

### Step 1: Start sotOs
```bash
just run-4pane &
# Wait for it to boot and open :18022 (SSH)
```

### Step 2: Identify Real Alpine Reference
- Provision an Alpine 3.20.x VM on the **same hypervisor** (or a peer LAN).
- Note its IP (e.g., 192.168.1.100).
- Ensure SSH :22 is accessible.

### Step 3: Run Evaluation
```bash
tools/eval/t2-tcp-fp/run.sh 127.0.0.1 192.168.1.100 10
# Or with defaults:
tools/eval/t2-tcp-fp/run.sh
# It will prompt for Alpine IP and use defaults (10 rounds, $PWD/t2-tcp-fp-results-<ts>)
```

### Step 4: Review Results
```bash
ls -la t2-tcp-fp-results-*/
cat t2-tcp-fp-results-*/t2-tcp-fp-table-*.md
cat t2-tcp-fp-results-*/t2-active-nmap-*.csv
```

## CSV Output Format

Example:
```csv
Field,Description,sotOs Value,Alpine Value,Match,Notes
TTL (SYN-ACK),T1/T2,64,64,YES,
IP-ID (SYN-ACK),T1 (TI class),0,1234,NO,Intentional spoofing technique
DF Bit (SYN-ACK),T1,1,1,YES,
Window (SYN-ACK),T1,64240,65535,NO,Path-dependent; OS variance
MSS,T1,1460,1460,YES,
Wscale,T1,10,10,YES,
Option Layout,T1,mss,nop,nop,sackperm,nop,ws,mss,nop,nop,sackperm,nop,ws,YES,
ECN Capable,T6,1,1,YES,
=== OS GUESS CONSENSUS ===,, Linux 4.19-5.18; Alpine Linux,Alpine Linux,YES,
nmap Confidence,Avg confidence %,92.0%,95.0%,,Higher is more certain
```

## Statistical Reporting

For the paper table:

```markdown
| Metric | Alpine (n=10) | sotOs (n=10) | Match | Discrepancy | Class |
|--------|---------------|-------------|-------|-------------|-------|
| TTL | 64±0 | 64±0 | YES | 0 | FP |
| IP-ID (SYN-ACK) | [1–1000] | 0 | NO | 100% | TI |
| IP-ID (ICMP) | [1–1000] | [1–1000] | YES | 0% | II |
| DF (SYN-ACK) | 1 | 1 | YES | 0 | FP |
| Window | 65535 (σ=0) | 64240 (σ=0) | NO | 1295 | FP |
| MSS | 1460 | 1460 | YES | 0 | FP |
| Wscale | 10 | 10 | YES | 0 | FP |
| **Pass** | — | — | — | **≥80%** | — |
```

Legend:
- **FP**: Fingerprinting field (host-determined OS signature)
- **TI**: TCP IP-ID class (per-connection vs global)
- **II**: ICMP IP-ID class (incremental)
- **Match**: Field concordance (YES/NO)
- **Pass Condition**: ≥80% matched fields

## Troubleshooting

### sotOs SSH :18022 Unreachable
- Ensure `just run-4pane` has booted to the sotShell prompt.
- Check justfile hostfwd config (should be :18022 → :22).
- If QEMU is running but SSH unavailable, the guest may still be booting.

### nmap: Target appears down
- Ensure SSH is listening on the target port (22).
- Use `ssh -v -p 18022 root@localhost` to test directly.
- Check firewall rules (sotOs may have egress filters).

### p0f: No signatures captured
- p0f requires root (libpcap sniffing): `sudo p0f ...`
- Ensure the interface parameter (-i) is correct (use `-i any` for all).
- Trigger a real SYN from another host while p0f is sniffing.

### nmap Confidence Too Low (<50%)
- Increase round count (default 10; try 20+).
- Some probes may timeout; repeat with longer timeouts (`nmap --max-retries 5`).
- If Alpine & sotOs differ, it may indicate a real fingerprinting delta.

## References

1. **RFC 9293**: Transmission Control Protocol (TCP)
2. **RFC 791**: Internet Protocol (IPv4)
3. **nmap OS Detection**: https://nmap.org/book/osdetect.html
4. **p0f v3**: https://lcamtuf.coredump.cx/p0f3/
5. **sotOs TCP/IP Code**:
   - src/sotnet/tcp.c (SYN-ACK builder, window, options)
   - src/sotnet/tcp_fp.c (IP-ID counter, DF, TTL)
   - include/sotnet/tcp_fp.h (API)

---

Generated: 2026-06-26
Experiment: T2 (TCP/IP Stack Fingerprinting)
Target: IEEE Paper Reproducibility
