# sotOs — reproducible evaluation harness (paper T1–T5, F1–F2)

Each experiment produces a table/figure for the paper and is **reproducible**: pin every
version (run `00-environment.sh` first), repeat N times, report central tendency **plus**
dispersion, and commit the scripts + CSVs + pcaps + logs as the artifact. Every table is
tied to a gate (paper §8) — that linkage IS the reproducibility proof.

## Run order
```
just build                              # fresh images
tools/eval/00-environment.sh            # pin + record ALL versions → environment.txt
just run-4pane    # or a headless boot; gives hostfwd :18022/:18080/:18443 + /tmp/sotos-*.log
tools/eval/t1-tls-fp/run.sh    5        # repeat 5x
tools/eval/t2-tcp-fp/run.sh    10       # >=10 for the ISN/IP-ID class stats
tools/eval/t3-shell-recon/run.sh        # vs a reference Alpine 3.20
tools/eval/t4-containment/soak.sh /tmp/p4b.log    # after scripts/v1.5-endurance-run.sh
tools/eval/t4-containment/antidos.sh /tmp/sotos-orch.log
tools/eval/t5-syscall/run.sh            # microbench (needs microbench.bin in the binstore)
tools/eval/t5-syscall/macrobench.sh     # CPython/Doom/GTK3 timing
```

## References needed (the controls)
- **nginx:alpine** pinned by digest (T1) — `docker run` with a known self-signed cert.
- **Alpine 3.20.x** on the SAME network path (T2/T3) — same hypervisor/virtio, same hop count.
- **FoxIO ja4** + a JARM tool + nmap + p0f + tcpdump + openssl on the host.

## Experiments
### T1 · TLS fingerprints (JA3S/JA4S/JARM)  (`t1-tls-fp/`)
- **Pass condition:** Median JA3S match rate = 1.0 (100%) across all 7 clients, p95 >= 0.8 (80%). Same for JA4S and JARM. Pass iff all 3 metrics × all 7 clients satisfy this criteria.
- **External deps (pin in environment.txt):** openssl (s_client, s_server, req), tcpdump (pcap capture), python3 (ja3s.py parsing, statistics), qemu-system-x86_64 (boot sotOs), tools/ja3s.py (shipped, stdlib only: struct/hashlib), build/images/kernel-x86_64-pc99 (from 'just build'), build/images/sotOs-root-image-x86_64-pc99 (from 'just build'), build/images/sotfs.img (from 'just build')

### T2 · TCP/IP stack (nmap -O, p0f)  (`t2-tcp-fp/`)
- **Pass condition:** Matched Fingerprint Fields / Total Fields ≥ 0.80 (80% concordance across n≥10 nmap rounds + p0f OS label = Alpine/Linux, not distinct signature); nmap average confidence ≥ 70%; both active (nmap -O) and passive (p0f) verdicts yield Alpine 3.20 or generic Linux OS class
- **External deps (pin in environment.txt):** nmap (OS fingerprinting), p0f v3 (passive fingerprinting), python3 (CSV/table generation), tcpfp.py & ipfp.py (existing sotOs pcap parsers)

### T3 · shell recon battery  (`t3-shell-recon/`)
- **Pass condition:** Structural divergence rate = 0 (zero structural divergences across all 30 commands aggregated over all iterations). Benign variance (timestamps, PIDs, uptime, random IDs) is masked and does NOT cause failure. Pass iff sum(structural_divergence_counts) == 0.
- **External deps (pin in environment.txt):** bash, ssh, python3 (3.6+), diff, grep, sed, awk, timeout, date, find, cat

### T4 · containment & memory soak  (`t4-containment/`)
- **Pass condition:** Survival% >= 99.7% (297/300 or better); Zero-Leak slope within [-0.2, +0.2] frames/spawn with 95%CI excluding zero-leak threshold of 1 frame/spawn; Fork-Bomb time-to-contain < 500ms; No kernel panic post-quarantine; Arena pool free_arenas returns to baseline after every reap (no leak); Leak mark (max residue) < 100 frames/spawn
- **External deps (pin in environment.txt):** seL4 kernel (x86_64, QEMU/KVM), Linux Alpine 3.20 / linux-lts 6.6.30 (attacker persona), sotOs built via just build, bash, python3 (matplotlib optional), socat, tmux (for just run-4pane), just >= 1.0

### T5 · syscall overhead  (`t5-syscall/`)
- **Pass condition:** All representative syscalls achieve < 20× overhead (Ratio column in table). Simple syscalls (getpid) baseline at ~3.5× due to fault interception cost. Complex syscalls (mmap, open) amortize to ~2.4–2.8× due to handler execution dominance. clock_gettime is exception (12×) because native uses VDSO while LUCAS intercepts for observability. Macro workloads (CPython startup 3.3×, Doom FPS 38% slowdown, GTK3 commits 47% slowdown) acceptable for deception honeypot use case.
- **External deps (pin in environment.txt):** Alpine 3.20 (linux-lts 6.6.30), QEMU 6.2+ with KVM support, gcc 12+ (for static compilation), x86_64 CPU with rdtsc support, seL4 kernel (external/kernel submodule), LUCAS runtime (src/lucas/)

## Notes
- T1/T2/T3/T5 scaffolds are grounded in the code (tls13.c, the SYN-ACK builder, the hostfwd
  ports, the syscall fault path) but some orchestration loops are marked TODO — complete them
  against the live host. T4 leverages the mature `scripts/soak.sh` gate.
- The microbench (T5) is a static guest binary — build + binstore it like the existing fixtures
  (see t5-syscall/CMakeLists.txt).
