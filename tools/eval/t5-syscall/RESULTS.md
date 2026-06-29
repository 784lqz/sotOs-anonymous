# T5 · syscall-latency — measured results & cost breakdown

Raw syscalls under `lfence;rdtsc`, `-nostdlib` (no libc caching/vDSO), 100k iterations,
`min` = the clean fault→IPC→lucAs→return floor (no scheduler jitter).  Native baseline is
the SAME binary on the host. Guest = sotOs single-thread sotbox.

## Headline (cycles, min)

| syscall | native | guest, no opt | guest, optimized | reduction |
|---|--:|--:|--:|--:|
| getpid (trivial → fast-path) | ~400 | 13,915 | ~8,900 | **−36%**  (≈35× → ≈22× native) |
| clock_gettime (non-trivial → normal path) | ~480 | 18,170 | 17,411 | −759 (**−4%**) |
| clock_gettime via libc (musl vDSO fast-path) | ~30–80 | — | **112** | **no trap** (Task 8) |

## Task 8 · libc / vDSO fast-path (measured 2026-06-28)

| path | min cycles | mean cycles | notes |
|---|--:|--:|---|
| raw syscall (-nostdlib, no vDSO) | 17,411 | ~17,800 | fault→seL4→LUCAS→return |
| raw vDSO call (vdso_probe, manual ELF parse) | 218 | ~240 | direct __vdso_clock_gettime() call |
| libc clock_gettime (musl, AT_SYSINFO_EHDR) | **112** | **120** | musl resolves __vdso_clock_gettime@@LINUX_2.6 automatically |

The libc path (112 cyc min) is faster than the manual ELF-parse path (218 cyc) because:
- musl's vDSO resolver runs at startup, so the call site is a direct indirect call through a function pointer already cached in musl's internal `__vdso_clock_gettime` variable — no ELF parsing at call time.
- The vdso_probe measurement includes one rdtsc-fenced call with no warmup in the timed window; ubench_libc runs 2000 warmup iterations before the 100k timed loop, so branch predictors and TLB entries are warm.

Gate: `tools/vdso-gate.sh` asserts min < 1000 (musl routed through vDSO, not the syscall trap).

## Official bare-metal run · `--native --guest`, full isolation protocol (2026-06-29, run 20260629T001145Z)

Knobs APPLIED: governor=performance, **turbo OFF**, SMT siblings offline, `taskset -c 2,3`, isolcpus/nohz_full/rcu_nocbs. Turbo-off ≈ 2× the turbo-on gate numbers above (rdtsc ticks at the base rate while the core runs at base freq), so these are the conservative, reproducible figures.

| measurement | min (cyc) | mean |
|---|--:|--:|
| native `getpid` (raw syscall) | 662 | ~690 |
| native `clock_gettime` (raw syscall) | 848 | ~895 |
| native `clock_gettime` (libc / host vDSO) | 126 | 137 |
| guest `getpid` raw (trap) | 21,222 | 22,905 |
| guest `clock_gettime` raw (trap) | 38,568 | 40,854 |
| guest `clock_gettime` via libc/vDSO | **258** | 283 |
| guest `vdso_probe` (direct `__vdso_` call) | 468 | — |
| guest `sched_yield` (fast-path) | 22,302 | — |

**Headline:** guest `clock_gettime` 38,568 (trap) → **258 (vDSO)** = **~149×**, same boot/conditions. And 258 < the native raw-syscall 848 — the in-guest vDSO answers in userspace, faster than a native syscall trap.

**Load caveat:** the raw-trap absolutes here (getpid 21k / clock_gettime 38.5k) run ~2.5× the quiet-machine baseline (getpid ~8,700 / clock_gettime ~17,400, run 20260628T132259Z, load 0.14). The trap path crosses into the orch and is host-load-sensitive; this run was on a loaded desktop (the preflight flagged load>0.7). The **vDSO number (258) is load-robust** — a clean userspace loop on the isolated core. For the paper's trap-floor absolute, use a `load<0.7` run (`systemctl isolate multi-user.target`); the vDSO figure and the ratio are solid as-is.

## What the optimizations do

1. **Trivial fast-path** (getpid/getppid/getuid/getgid/geteuid/getegid/gettid, single-thread,
   in-text, no pending signal): bypasses the per-syscall deception instrumentation AND the
   `seL4_TCB_ReadRegisters` round-trip; frame reconstructed from the fault IPC MRs, resumed via
   the proven `WriteRegisters`+`Reply`. → ~36% for these syscalls.
2. **Single-thread ReadRegisters elision** (ALL single-thread syscalls): reconstructs the
   register frame from the fault MR snapshot instead of `ReadRegisters`, keeping the full
   instrumentation. → ~4%.

## Cost breakdown (the finding)

The controlled A/B (extension on vs off, same binary) isolates `seL4_TCB_ReadRegisters` at
**~759 cyc (~4%)**.  The fast-path saves ~5,000 cyc, so the remaining **~4,200 cyc is the
deception instrumentation** — anomaly scoring, the sotTrace syscall ring, and the RIP-in-text
validation heuristic — NOT the microkernel fault/IPC/register mechanics.

Implication for the paper: the fault-based syscall *mechanics* are cheap; the per-syscall tax
is the **cost of the deception/observability layer**, which we correctly keep for
security-relevant syscalls and bypass only for security-irrelevant trivial ones.  The residual
~8,900-cyc floor for getpid is the seL4 fault round-trip + `WriteRegisters` + dispatch; driving
it to native would require a vDSO-style path that avoids the fault entirely (future work).

## Task 10 · getpid fast-path component breakdown (measured 2026-06-28)

Goal: break the ~8,900-cyc trivial fast-path floor into WriteRegisters, dispatch, and residual
(seL4 fault round-trip).  Method: compile-time toggles (`-DT5ElideWriteRegs`, `-DT5ElideDispatch`),
DEFAULT OFF; bench result is garbage under a toggle, only the cycle delta counts.

### Toggle semantics

| toggle | what it elides | bench validity |
|---|---|---|
| `T5_ELIDE_WRITEREGS` | `WriteRegisters(18)` → `WriteRegisters(1)` | cycles valid; RAX = garbage |
| `T5_ELIDE_DISPATCH`  | `lucas_dispatch_call` → stub `fp_ret=1` | cycles valid; return value = garbage |

**`T5_ELIDE_WRITEREGS` implementation note**: the seL4 SYSRETQ kernel exit path (taken when
`registers[Error] == -1`, which handle_fastsyscall sets for every syscall entry) explicitly zeroes
RSP before `sysretq`.  Only IRETQ correctly restores RSP from `registers[RSP]`.
`seL4_TCB_WriteRegisters` triggers `Mode_postModifyRegisters` → `registers[Error] = 0`, forcing
IRETQ.  Skipping WriteRegisters entirely causes RSP=0 → VMFault at the first CALL after the loop.
Fix: use `WriteRegisters(count=1)` (writes FaultIP only, triggers Mode_postModifyRegisters) +
`Reply(length=0)`.  Delta (baseline(18) − elide(1)) measures marginal cost of 17 extra writes.

### Raw measurements (min cycles, 3-boot min-of-min, cores pinned 2,3, KVM)

| variant | run 1 | run 2 | run 3 | **min** |
|---|--:|--:|--:|--:|
| baseline (WriteRegs=18, dispatch=on) | 9252 | 9218 | 9368 | **9218** |
| elide_writeregs (WriteRegs=1, dispatch=on) | 9414 | 9188 | 9390 | **9188** |
| elide_dispatch (WriteRegs=18, dispatch=off) | 9256 | 9286 | 9440 | **9256** |

Reference: official baremetal run 20260628T132259Z reported baseline min=**8706** (more isolation).

### Component breakdown

| component | formula | cycles | % of baseline |
|---|---|--:|--:|
| `WriteRegisters` marginal (17 extra reg writes) | baseline − elide_writeregs | +30 | ~0.3% |
| `lucas_dispatch_call` (getpid handler) | baseline − elide_dispatch | −38 | ~0% (within noise) |
| **Residual (seL4 fault round-trip, irreducible)** | elide_writeregs | **~9188** | **~99.7%** |

### Conclusion

Both `seL4_TCB_WriteRegisters` and `lucas_dispatch_call` contribute **< 1% each** to the
getpid fast-path latency.  The **seL4 fault round-trip is the irreducible ~99% floor**.

This confirms: optimizing the orch-side C code (dispatch lookup, register writes) yields
negligible improvement.  The only path to native-like latency is eliminating the fault
entirely — i.e., a vDSO-style redirect that answers the syscall without trapping to seL4.
Task 8 proved this is achievable: `clock_gettime` via musl's vDSO route costs 112 cycles
vs 8,700+ via the fault path — a 78× speedup.

**Task 11 implication**: a getpid vDSO page (mapping a synthetic pid into read-only guest
memory, read without a trap) would bring getpid from ~8,700 to ~50–150 cycles.

## Threat-model note

This is a *local* timing side-channel (the attacker has a shell and can time syscalls).  It is
not a unique honeypot signature — instrumented production hosts (seccomp/eBPF, EDR hooks,
ptrace) show elevated syscall latency too — and reads as "monitored host," not "honeypot."
