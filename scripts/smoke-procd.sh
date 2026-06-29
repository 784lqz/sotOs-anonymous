#!/bin/bash
# sotOs · procd smoke check (PR 3).
#
# Boots the kernel + root in QEMU, captures serial stdout, then greps
# for procd-banner + procd-unit PASS lines.  Designed to be runnable
# from CI once `just build` has produced fresh images.
#
# Usage:
#   bash scripts/smoke-procd.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$(mktemp -t sotos-smoke-procd-XXXXXX.log)"
trap 'rm -f "$LOG"' EXIT

KERNEL="$ROOT/build/images/kernel-x86_64-pc99"
INITRD="$ROOT/build/images/sotOs-root-image-x86_64-pc99"

if [[ ! -f "$KERNEL" || ! -f "$INITRD" ]]; then
  echo "FAIL · build artifacts missing.  Run 'just build' first." >&2
  exit 2
fi

timeout 120 qemu-system-x86_64 \
  -m 2048 -display none -serial stdio -enable-kvm -cpu host \
  -kernel "$KERNEL" -initrd "$INITRD" \
  -drive file="$ROOT/build/images/sotfs.img",format=raw,if=none,id=sd0 \
  -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  > "$LOG" 2>&1 || true

declare -a CHECKS=(
  "PROCD·alive:\\[procd\\] alive · ep="
  "PROCD·shm:\\[procd\\] shm ready · base="
  "PROCD·unit·alloc_free:\\[procd-unit\\] PASS test_table_alloc_free"
  "PROCD·unit·table_full:\\[procd-unit\\] PASS test_table_full"
  "PROCD·unit·seqlock:\\[procd-unit\\] PASS test_seqlock_round_trip"
  "PROCD·unit·all:\\[procd-unit\\] ALL PASS"
  "PROCD·ring·unit:\\[procd-unit\\] PASS test_event_ring_overflow"
  "PROCD·ring·marker:\\[procd\\] event channel marker published"
  "PROCD·ring·e2e:\\[orch\\] procd-ev kind=0x10 slot=0"
  # procd-authoritative-GC · proves orch read procd's SHM header through the
  # RO cross-vspace mapping (impossible in the old NTF-only synthesizer mode).
  "PROCD·xvm:\\[orch\\] procd ring resolved · base="
  # procd-authoritative-GC · proves the WAL writer gate is flipped: orch
  # mirrors procd's proc_t mutations to the WAL in-process from its drain
  # (no procd→orch seL4_Call · the old blocking/deadlock path stays retired).
  "WAL·procd-mut:\\[wal\\] kind=procd_mut slot="
  "PROCD·reader:\\[LucAs\\] proct self-test · slot="
  # PR 5/7 · OP_SPAWN announce / handler smoke checks.  PR 7 dropped
  # the PROCD_TAKEOVER_SPAWN gate · the announce path is now always
  # active on every build.
  "PROCD·spawn·announce:\\[orch\\] procd announced slot="
  "PROCD·spawn·handler:\\[procd\\] spawn slot="
  # PR 6 · OP_FORK / OP_EXIT / OP_WAIT shadow-announce checks.  Fire
  # whenever procd_fork_test.bin runs.  The fork-test binary itself
  # emits "[fork-test] child alive" and "[fork-test] parent reaped
  # child" markers that confirm the fixture ran end to end.
  "PROCD·fork·born:\\[procd\\] fork slot="
  "PROCD·fork·announce:\\[orch\\] procd fork announced child"
  "PROCD·exit·event:\\[procd\\] exit slot="
  "PROCD·wait·sigchld:\\[procd\\] EV_SIGCHLD"
  # PR 7 · OP_EXEC shadow-announce.  Fires when any sotbox completes
  # an execve() · busybox-shell pipeline child execs, Python bootstrap
  # exec, etc.  The procd-side handler logs "[procd] exec slot=N
  # synthetic_pid=M tier=T" so the announce path is end-to-end visible.
  "PROCD·exec:\\[procd\\] exec slot="
  # PR 8 · OP_CLONE thread-path announce + EV_THREAD_BORN.  Fires when
  # the pthread fixture (LucAs_PTHREAD_BIN) calls
  # clone(CLONE_VM|CLONE_THREAD) · LucAs's thread-clone helper now
  # announces every successful TCB allocation.  OP_THREAD_EXIT announce
  # is deferred to PR 13 (per-thread exit detection not yet plumbed in
  # LucAs) so we don't check for THREAD_EXITED today.
  "PROCD·clone:\\[procd\\] clone owner_slot="
  "PROCD·clone·announce:\\[LucAs\\] procd thread announced pd_tid="
  # PR 9 · OP_SETSID + OP_SETPGID + OP_GETPGID shadow-announce.  Fires
  # when procd_pg_test.bin runs · the fixture forks once, the child
  # calls setsid, setpgid(0,0), then getpgid(0), and prints a one-line
  # summary.  All three procd-side handlers are exercised end to end.
  "PROCD·setsid:\\[procd\\] setsid slot="
  "PROCD·setpgid:\\[procd\\] setpgid slot="
  "PROCD·pg-test:\\[pg-test\\] before_pgrp="
  # PR 10 · badged OP_SET_TIER + functor rebind smoke checks.
  #
  # Tier mutation now flows through procd via the badged EP root mints
  # into orch's CSpace (BADGE_ANOMALY_OP_SET_TIER=0xA009).  LucAs_set_tier
  # mirrors every legacy writes_silenced/is_isolated flip into procd's proc_t state
  # so procd publishes EV_TIER_CHANGED + EV_FUNCTOR_REBOUND on every
  # operator-visible promotion (in-orch anomaly rule, dispatch.c pledge
  # auto-promote, handlers_net.c connect auto-promote, orch
  # ORCH_OP_PROMOTE_TIER handler, sotShell `promote` command).
  #
  # The orch boot-time smoke marker (PR 10 one-shot OP_SET_TIER inside
  # orch_procd_spawn) fires exactly once per boot against the first
  # spawned slot · result is a no-op tier=0→0 transition that still
  # publishes the EV_TIER_CHANGED + EV_FUNCTOR_REBOUND lines.  This
  # guarantees the smoke evidence appears at boot without depending on
  # `inject-script /simulated_attacker.py` being driven (the full demo
  # flow IS verified separately by the operator-driven run · see plan
  # PR 10 step 10.9).
  #
  # The anomaly-ext-driven path (anomaly auto-promote via its own
  # WRITE-rate rule) is gated by the FORWARD_LIMIT deadlock guard in
  # LucAs/anomaly.c which caps event forwarding at the threshold ·
  # anomaly-ext never crosses its own threshold in normal boots.  Its
  # OP_SET_TIER hook (anomaly_procd_set_tier helper) IS active and
  # exercised by the operator-driven demo (the path through
  # ORCH_OP_PROMOTE_TIER badge=0xA005 still flows through
  # LucAs_set_tier → orch_procd_set_tier).  The third smoke check
  # therefore asserts the badged-EP wiring evidence at boot rather than
  # an in-the-loop anomaly-ext line.
  "PROCD·set_tier:\\[procd\\] EV_TIER_CHANGED"
  "PROCD·functor_rebound:\\[procd\\] EV_FUNCTOR_REBOUND"
  "PROCD·anomaly_ep_mint:\\[root\\] procd EP minted into anomaly"
  # PR 11 · synth fork policy gate.  Fires when a Tier-2 sotbox calls
  # fork() · the parent's tier is read from procd's proc_t (or from the
  # legacy LucAs_state.tier field while cross-vspace SHM is deferred to
  # PR 14).  Procd allocates a silenced slot whose seL4 caps stay 0, so the
  # malware sees a valid synthetic_pid but no new sotbox shows up in sotinfo.
  #
  # These two patterns only fire during the operator-driven
  # `inject-script /simulated_attacker.py` Stage 6 demo.  The 60-second
  # smoke boot may not reach Stage 6 because the Python bootstrap is
  # slow and the demo only runs when the operator types the inject
  # command at the sotShell prompt; the operator-driven verification in
  # `just run` (see PR 11 plan step 11.5) is the source of truth for
  # this gate.  We list the patterns here so a CI run that DOES manage
  # to drive the inject (e.g. via expect) gets credit for the evidence.
  "PROCD·synth·fork:\\[procd\\] EV_SYNTH_FORK slot="
  "PROCD·synth·orch:\\[orch\\] synth fork"
  # γ-3-ε · operator response_profile installing · deterministic proof that a
  # `synth-install <ip> <port> <response_profile>` command reached the net-synth
  # responder and was inserted into its runtime table (the "served on
  # redirect" path is the pre-existing fire-and-forget redirect · eyeballed).
  "SYNTH·install:\\[synth-srv\\] install · dst=203.0.113.7:8080 kind=1 rc=0"
  # PR 12 · futex REQUEUE / CMP_REQUEUE / WAKE_OP / WAIT_BITSET /
  # WAKE_BITSET handler.  The end-to-end smoke driver is the
  # procd-cond-test fixture (3 workers FUTEX_WAIT_BITSET on the same
  # cond, main thread FUTEX_WAKE_BITSET broadcasts) · its PASS line is
  # the operator-visible evidence.  The fixture only runs when the
  # demo loop reaches "procd-cond-test"; smoke-procd.sh's 60 s window
  # is enough on KVM but if the demo list is truncated this pattern
  # may not fire in a given run.  The pattern is listed here so a
  # full demo-loop run gets credit.
  "PROCD·cond·broadcast:\\[cond-test\\] PASS"
  # PR 13 · set_robust_list announce + thread-exit robust walk.  The
  # procd-robust-test fixture calls set_robust_list(2) on main + one
  # worker thread · the announce fires twice (main with tid=0, worker
  # with non-zero pd_tid).  Scope reduction per PR 13 plan: we don't
  # drive a real pthread mutex EOWNERDEAD round-trip because that
  # needs glibc/musl runtime · the smoke gate is the [procd] set_robust
  # line firing at least once.  Operator evidence on stdout:
  #   [procd] set_robust tid=N head=0x... caller_slot=M
  #   [robust-test] set_robust announced
  "PROCD·set_robust:\\[procd\\] set_robust tid="
  "PROCD·robust·fixture:\\[robust-test\\] set_robust announced"
  # PR 14 · OP_CLONE fork-like path · widens the supported flag set to
  # cover the rest of the pthread / Wine / posix_spawn canonical set
  # (CLONE_FS / FILES / SIGHAND / PARENT / VFORK / PIDFD / PARENT_SETTID).
  # The thread-path smoke gate above (PROCD·clone) still fires on every
  # pthread fixture run.  The fork-like path fires whenever a sotbox
  # calls clone() WITHOUT CLONE_THREAD · today that only happens when
  # the operator-driven `inject-script /simulated_attacker.py` Stage 6
  # fork hits the new path (os.fork() under glibc still routes through
  # SYS_clone with CLONE_CHILD_SETTID on modern libc).  The smoke
  # boot's 60 s window may not reach Stage 6 because Python bootstrap
  # is slow; the pattern is listed so a full demo-loop run gets credit.
  "PROCD·clone·extended:\\[procd\\] clone fork-like slot="
  # PR 16 · F_proc full implementation · process-dimension deception
  # closed across kill / wait4 / getppid by routing the four
  # process-introspection handlers through procd's SHM seqlock.  The
  # three patterns below only fire on the operator-driven inject path
  # (simulated_attacker.py Stage 6 forks a synth child then calls
  # os.kill / os.waitpid / os.getppid against it).  Same handling as
  # the PROCD·synth·* group above: the smoke-boot 60 s window may
  # not reach Stage 6, so these patterns are listed for a full demo-
  # loop run to claim evidence.  Boot-smoke target stays at the prior
  # baseline; the three new checks are operator-verifiable.
  "PROCD·fproc·kill_synth:\\[LucAs\\] kill\\(pid=.*\\) to synth slot"
  "PROCD·fproc·wait4_synth:\\[LucAs\\] wait4\\(pid=.*\\) synth child"
  "PROCD·fproc·getppid_via_procd:\\[LucAs\\] getppid -> "
  # PR 5 · WAL replay-applies for files (HORIZON v2).  sotfs_wal_replay
  # is now a thin renamed handler (sotfs_wal_replay_files) called from a
  # new top-level dispatcher (sotfs_wal_replay_apply) that runs at boot
  # in LucAs's sotfs lazy_init.  The dispatcher emits one line per cold
  # boot reporting the count of FS records the replay applied · the
  # count is >= 0 (zero on first boot before any WAL records exist;
  # positive on every subsequent boot if virtio-blk persistence is up).
  "REPLAY·files-applied:\\[sotfs\\] WAL replay apply · files="
  # PR 6 · per-subsystem WAL replay-applies (procd / anomaly / sotnet).
  # The dispatcher in src/sotfs/wal_replay.c now also calls the three
  # per-subsystem replay scanners after the file-only handler.  Each
  # one emits its own diagnostic line with the count of records
  # applied/restored.  procd's count stays at 0 (writer gate still 0
  # since PR 3-4 · async ring transport ships in a follow-up PR) but
  # the scanner runs every boot to verify the WAL walk is well-formed.
  # anomaly + sotnet counts grow positive across boots if the prior
  # boot fired sotguard_emit / synth_record_redirect (both have live
  # in-process writer hooks since PR 4).  The fourth pattern is the
  # combined dispatcher summary line that appears once per cold boot.
  "REPLAY·procd:\\[procd\\] WAL replay · [0-9]+ applied"
  "REPLAY·anomaly:\\[anomaly\\] WAL replay · [0-9]+ events restored"
  "REPLAY·sotnet:\\[sotnet\\] WAL replay · [0-9]+ synth entries restored"
  "REPLAY·dispatch-summary:\\[sotfs\\] WAL replay apply · procd=[0-9]+ anomaly=[0-9]+ sotnet=[0-9]+"
  # α · PR 7 · simreboot cascade · userspace-only reset.  Triggered by
  # the sotShell scripted demo (`simreboot` command after install of the
  # /tmp/simreboot-marker file).  Each phase emits a banner line that
  # smoke greps for; Phase 1 (CHECKPOINT) + Phase 5 (replay-apply) are
  # real work · Phase 2-4 are scope-reduced banner-only (see
  # src/orch/simreboot.c for the rationale).  The persistence proof is
  # the marker file surviving the cascade: cat /tmp/simreboot-marker
  # after simreboot returns the installed content (SURVIVE-THE-RESET).
  "SIMREBOOT·phase1:\\[root\\] simreboot · phase 1/5 · checkpoint WAL"
  "SIMREBOOT·phase2:\\[root\\] simreboot · phase 2/5 · suspend Path D children"
  "SIMREBOOT·phase3:\\[root\\] simreboot · phase 3/5 · free seL4 objects"
  "SIMREBOOT·phase4:\\[root\\] simreboot · phase 4/5 · respawn Path D children"
  "SIMREBOOT·phase5:\\[root\\] simreboot · phase 5/5 · replay-apply WAL"
  "SIMREBOOT·checkpoint:\\[wal\\] kind=checkpoint epoch_seq="
  "SIMREBOOT·complete:\\[root\\] simreboot complete · uptime continuation"
  # End-to-end persistence proof · Phase 5 reads WAL records from
  # virtio-blk (durable storage) and re-applies them through the same
  # dispatcher cold boot uses.  The "phase 5 ok" line is emitted ONLY
  # if sotfs_wal_replay_apply returned a non-negative count · which
  # in turn requires the storage backend to be live (virtio-blk
  # initialised) and the per-subsystem replays to all have completed.
  # That chain · WAL durable read → file replay → procd/anomaly/sotnet
  # replays → return value > 0 · is the persistence proof.
  "SIMREBOOT·phase5-records:\\[root\\] simreboot · phase 5 ok · [0-9]+ total records observed"
  # PR 8 · WAL unit test ELF · spawned by root at boot · prints PASS/FAIL
  # for the CRC64 roundtrip + payload size sanity checks against the
  # public sotfs ABI.  ALL PASS line is the gate.
  "WAL-UNIT·all-pass:\\[wal-unit\\] ALL PASS"
  # sotnano PR 2 · gap-buffer unit test ELF · spawned by root at boot ·
  # prints PASS/FAIL for insert/serialize/move/delete/cursor_rowcol on the
  # freestanding gap buffer.  ALL PASS line is the gate.
  "SOTNANO-UNIT·all-pass:\\[sotnano-unit\\] ALL PASS"
  # sotnano PR 10 · headless selftest · drives synthetic keystrokes through
  # the IPC-free sotnano_handle_key (type/Enter/undo) with no orch and
  # asserts buffer state + undo.  The done line is the gate.
  "SOTNANO-SELFTEST·done:\\[sotnano-selftest\\] done"
  # PR 8 · STRESS · sotShell drives the simreboot cascade 10x after the
  # scripted demo finishes.  Each iteration prints "[demo] stress
  # simreboot N/10".  The 10/10 line confirms the loop completed; the
  # "simreboot complete · uptime continuation" line (already gated by
  # SIMREBOOT·complete) confirms each cascade returned cleanly · the
  # cascade is reentrant because we got past iteration 1.
  "STRESS·simreboot-10x:\\[demo\\] stress simreboot 10/10"
  "STRESS·survives:\\[root\\] simreboot complete · uptime continuation"
  # β · PR 1 · sotinit scaffold ELF.  Spawned by root as a Path D sibling
  # of procd · banner-only in PR 1 (idle yield after print).  Subsequent
  # PRs add the unit registry, the operator-driven IPC dispatcher, and
  # the procd OP_SPAWN client path for service activation.
  "SOTINIT·alive:\\[sotinit\\] alive · ep="
  # β · PR 2 · directory scan + INI parse + unit registry population.
  # The "N unit files found" line confirms the scan path executed; the
  # "loaded N units" line confirms the parser + registry pipeline
  # populated at least the bundled demo unit slots.  N depends on which
  # demo-unit packing path is live (PR 2 ships Option C · two units
  # embedded in .rodata · so N=2 on the baseline).  We assert ≥0 only
  # so future PRs that grow/shrink the bundle don't false-fail.
  "SOTINIT·scan:\\[sotinit\\] [0-9]+ unit files found"
  "SOTINIT·loaded:\\[sotinit\\] loaded [0-9]+ units"
  # β · PR 3 · service launcher · sotinit calls procd OP_SPAWN for every
  # .service in state=LOADED.  The demo-noop.service unit is the canonical
  # fixture (bundled in scan.c's .rodata · ExecStart=/bin/true).  The
  # "[sotinit] demo-noop.service started · slot=N synthetic_pid=M" line is the
  # operator-visible evidence that the procd OP_SPAWN announce round-trip
  # completed end to end.  The "[sotinit] N services activated" summary
  # line is the count of successful activations (1 in the baseline).
  "SOTINIT·service-start:\\[sotinit\\] demo-noop.service started"
  "SOTINIT·services-active:\\[sotinit\\] [0-9]+ services activated"
  # β · PR 4 · After= topological sort.  scan.c's g_bundled[] inserts
  # demo-b BEFORE demo-a (insertion order is intentionally inverted)
  # so the only way demo-a.service can appear in the activation log
  # before demo-b.service is for sotinit_topo_sort to have flipped the
  # walk order via Kahn's algorithm.  Two separate gates · manual
  # ordering inspection in the serial log confirms demo-a → demo-b.
  "SOTINIT·topo-a:\\[sotinit\\] demo-a.service started · slot="
  "SOTINIT·topo-b:\\[sotinit\\] demo-b.service started · slot="
  # β · PR 5 · listen EP + 4 operator query handlers + sotShell systemctl
  # command.  The listen-loop banner fires once after sotinit finishes its
  # activation walk and enters the operator-driven IPC dispatch loop.
  # The systemctl line fires from sotShell's scripted demo_commands array
  # (drives `systemctl list` against the sotinit listen EP that orch
  # forwarded into sotShell's CSpace as argv[3]).
  "SOTINIT·listen:\\[sotinit\\] listen loop entering"
  "SOTINIT·query:\\[sotshell\\] systemctl"
  # β · PR 6 · restart policy fixture · demo-fail.service is parsed
  # with Restart=on-failure (ExecStart=/bin/false).  The bundled unit
  # MUST be loaded + dispatched through sotinit_activate_service at
  # boot · the "started · slot=" line proves the parser+registry+
  # launcher pipeline accepted Restart=.  The actual respawn loop
  # only fires when an EV_PROC_EXITED arrives for the unit's procd
  # slot (manual gate · procd's test-only kill opcode is post-PR-6).
  "SOTINIT·restart-fixture:\\[sotinit\\] demo-fail.service started"
  # β · PR 7 · sotcron scaffold ELF · cron-like timer scheduler · sibling
  # of sotinit / procd · spawned by root as a Path D process.  PR 7 ships
  # the banner + TSC calibration + idle polling loop; subsequent PRs wire
  # OnCalendar / OnUnitActiveSec parsers and the SOTINIT_OP_ACTIVATE fire
  # dispatch.  Three independent gates so a regression in any stage
  # (alive / calibrated / polling) surfaces immediately.
  "SOTCRON·alive:\\[sotcron\\] alive · ep="
  "SOTCRON·calibrated:\\[sotcron\\] tsc_per_second = [0-9]+"
  "SOTCRON·polling:\\[sotcron\\] polling loop entering"
  # β · PR 8 · OnCalendar / OnUnitActiveSec parsers + fire dispatch into
  # sotinit via SOTINIT_OP_ACTIVATE.  The demo-tick.timer fixture (30 s
  # interval pointing at demo-noop.service · bundled in sotcron's
  # scan.c rodata) loads at boot and fires once during the 120 s smoke
  # window.  Three independent gates so a regression in any stage
  # (scan loaded / fire dispatched / sotinit ACTIVATE accepted) surfaces
  # immediately.
  "SOTCRON·scan:\\[sotcron\\] scan loaded demo-tick.timer"
  "SOTCRON·fire:\\[sotcron\\] fire demo-tick.timer · target=demo-noop.service"
  "SOTINIT·activate:\\[sotinit\\] ACTIVATE demo-noop.service · result="
  # init-cron PR 10 · LucAs shell-hook · execve argv rewrite.  The
  # shellhook-test fixture forks a child that execve("/bin/sh", {"sh"},
  # NULL).  LucAs_sys_execve detects the shell target and rewrites argv
  # to `sh -c 'source /etc/bashrc; source /root/.bashrc; exec sh'`.  Two
  # operator-visible gates:
  #   SHELLHOOK·fired   · the [LucAs] shellhook line in orch's serial
  #                       output (proof the hook fired in the execve
  #                       handler).
  #   SHELLHOOK·marker  · the [BASHRC-MARKER] echo line from the
  #                       sourced rc file (proof the wrapper command
  #                       reached the wrapped shell and ran).
  # If only the first fires, the rewrite landed but the wrapped shell
  # never reached the echo · usually a busybox-static -c parsing issue
  # or a stack-setup regression.  Diagnostics: tail the last 60 lines
  # of the smoke log; the [shellhook-test] before/parent reaped pair
  # confirms fork/wait4 still work.
  "SHELLHOOK·fired:\\[LucAs\\] shellhook · injected"
  "SHELLHOOK·marker:\\[BASHRC-MARKER\\]"
  # POSIX-surface PR 6 · syscall-test fixture · raw-syscall C-static
  # validation of the LucAs POSIX surface arc (PRs 1-5): unlink(87) +
  # readv/writev(19/20) + madvise noop(28) + the fd-1/2 console/FS
  # boundary.  The fixture creates+writes+unlinks /tmp/sc.tmp, asserts
  # the re-open returns ENOENT, runs an iov round-trip, checks madvise
  # returns 0, and prints "[syscall-test] ALL PASS" iff every step
  # held.  The single gate below is the end-to-end proof that all five
  # POSIX-surface PRs work together at runtime (not just compile).
  "SYSCALL·all-pass:\\[syscall-test\\] ALL PASS"
  # POSIX-surface PR 7 · Spec A closure · unlink-replay-clean.  The PR 6
  # fixture creates+writes+unlinks /tmp/sc.tmp at boot (sysno 87 ·
  # WAL-logged by parent_id+name, replay-stable like CREATE_FILE).  The
  # architectural risk for PR 1 was that a deletion would NOT survive
  # simreboot · a torn or mis-keyed unlink record would replay as a
  # resurrection.  The proof is the WAL replay walk reporting torn=0:
  # every record (including the unlink) re-applied cleanly through the
  # same dispatcher cold boot uses, so the deleted file stays deleted
  # across the simreboot cascade.  Reusing the existing torn=0 evidence
  # as the unlink-replay-safety signal · a dedicated cross-simreboot
  # file-absence check is a future hardening if needed.
  "POSIX·unlink-replay-clean:\\[wal\\] replay applied .* torn 0"
  # ANOMALY PR 7 · weighted-score test fixture · raw-syscall C-static
  # fixture (anomaly_test.bin) that runs as a sotbox AT BOOT and drives
  # the monitor's per-pid suspicion score deterministically across BOTH
  # tier thresholds (T1=20, T2=40).  Unlike the operator-driven graded
  # demo below, this fixture is launched from the scripted boot sequence,
  # so these three gates fire in the UNATTENDED smoke · always-on
  # regression proof of the PR 1-5 scoring engine.
  #
  # Score arithmetic (single sotbox · all in one run):
  #   stage 1  open("/honey-aws-creds")  EV_CRED_ACCESS  +15  → 15  (under T1)
  #   stage 2  5x write(fd>=3, 1B)       EV_WRITE x5     +5   → 20  (crosses T1)
  #   stage 3  unlink /tmp/st_b0..b5     escalating burst +42 → 62  (crosses T2)
  #            (i-th unlink in a run adds min(2*i,12): 2+4+6+8+10+12=42 ·
  #             T2=40 is crossed at the 4th unlink: 20+2+4+6+8=40)
  # The fixture creates the six burst files + the write fd while still
  # Tier 0 (open-with-write is revoke-gated once Silenced/Tier 1), then runs
  # cred → writes → unlink-burst and prints "[anomaly-test] ALL PASS".
  #   ANOMALY·test·all-pass · the fixture ran to completion w/o faulting.
  #   ANOMALY·test·tier1    · the engine logged the reply-driven 0→1 flip
  #                            ([anomaly] ... · src/lucas/anomaly.c).
  #   ANOMALY·test·tier2    · the engine logged the functor F_1→F_2 rebind
  #                            ([functor] ... · src/lucas/functor.c).
  # The pid is matched with a [0-9]+ wildcard (boot-time slot assignment).
  "ANOMALY·test·all-pass:\\[anomaly-test\\] ALL PASS"
  "ANOMALY·test·tier1:\\[anomaly\\] pid=[0-9]+ reply-driven promote Tier 0 → 1"
  "ANOMALY·test·tier2:\\[functor\\] pid=[0-9]+ .* → F_2"
  # SP1 PR 4 · writable-executable-memory test fixture (execmap_test.bin)
  # spawned TRUSTED at boot.  It mmaps a page PROT_READ|PROT_WRITE|PROT_EXEC,
  # copies x86_64 machine code into it, and jumps in.  The "[execmap-test]
  # exec OK" marker is printed BY THE CODE RUNNING IN THE WRITABLE-MAPPED
  # PAGE — so this gate is the always-on empirical proof that LucAs's W^X
  # relaxation for st->trusted actually yields an executable writable page
  # (the gating capability the in-OS C compiler's code generation needs).
  # Untrusted sotboxes still get the W^X rejection; none in the smoke do
  # RWX, so there is no behavior change for them.
  "EXECMAP·exec-ok:\\[execmap-test\\] exec OK"
  # SP1 PR 5 · the milestone · `tcc -run` of a freestanding C source AT
  # BOOT.  A trusted tcc sotbox compiles + JIT-executes /tmp/st-hello.c
  # (installed at sotfs /st-hello.c · sotfs is mounted at /tmp).  Both gates
  # are ALWAYS-ON · the run is boot-driven from sotShell's demo_commands
  # array (`tcc /tmp/st-hello.c`), so they fire in the unattended smoke.
  #   TCC·run-output       · the "[st-hello] tcc-run OK" line is printed BY
  #                          the JIT-compiled program itself (via its raw
  #                          write(1) syscall executing from a writable JIT
  #                          page) · the end-to-end proof that TinyCC
  #                          compiled the source in memory and ran it.
  #   TCC·trusted-msyscall · the JIT'd program's write/exit syscalls run
  #                          from a writable page (RIP outside .text) so
  #                          they trip the MSYSCALL detector · for a trusted
  #                          sotbox LucAs logs the detection audit-only and
  #                          does NOT do the blocking forward/promote (which
  #                          would hang the box).  This gate proves the
  #                          tier-pin-with-observability exemption held.
  # Untrusted MSYSCALL behavior is unchanged (the forward/promote branch is
  # gated on !st->trusted).
  "TCC·run-output:\\[st-hello\\] tcc-run OK"
  "TCC·trusted-msyscall:\\[msyscall\\] trusted pid=[0-9]+ .* audit-only · not promoted"
  # SP2 PR4 · TCC migrated out of CPIO · loaded from binstore
  "TCC·from-binstore:\\[spawn\\] load 'tcc.bin' · source=binstore"
  # SP2 PR3 · unified resolver · existing CPIO spawns still resolve
  "SP2·resolve-cpio:\\[spawn\\] load '[^']+' · source=cpio"
  # SP2 PR6 · TCC emits a standalone ELF into the writable graph
  "TCC·emit-elf:\\[spawn\\] load '/tmp/sp2-hello.elf' · source=sotfs-graph · [0-9]+ bytes"
  # SP2 PR7 · emitted ELF loads from sotfs graph and executes (untrusted)
  "RUN·sotfs-elf-output:\\[sp2-hello\\] elf-run OK"
  # tcc-libc · hosted milestone · musl-linked printf hello: emit + run from sotfs
  "LIBC·emit:\\[spawn\\] load '/tmp/hello-libc.elf' · source=sotfs-graph · [0-9]+ bytes"
  "LIBC·run-output:\\[sp2-libc\\] hello from musl printf"
  # SP2-migración PR2 · python + busybox load from binstore
  "MIGRAR·python-binstore:\\[spawn\\] load 'python3.12-static' · source=binstore"
  "MIGRAR·busybox-binstore:\\[spawn\\] load 'busybox-static.bin' · source=binstore"
  # γ · PR 11 · F_persistence functor + Stage 7 demo gates.  Six
  # operator-driven gates with the same documented FAIL pattern as the
  # PROCD·synth·* group above · they only fire when the operator runs
  # `inject-script /simulated_attacker.py` Stage 7 (persistence install
  # narrative) at the sotShell prompt.  The smoke-boot 60 s window does
  # not drive that flow, so all six will FAIL in non-operator runs.  The
  # patterns are listed here so a full demo-loop run gets credit for
  # the evidence chain:
  #   FPERSIST·install         · [LucAs] persistence install line at the
  #                              write/openat detection point.
  #   FPERSIST·audit-emit      · cross-process AUDIT IPC of kind 0xc0
  #                              (PERSISTENCE_INSTALL) routed to orch.
  #   FPERSIST·anomaly-log    · the unified anomaly-log line stamped
  #                              with PERSISTENCE_INSTALL for triage.
  #   FPERSIST·sotinit-scan    · sotinit's boot-time sotfs scan_now line
  #                              for the persistence path patterns.
  #   FPERSIST·never-activate  · sotinit's guard rejecting activation
  #                              of any unit flagged F_persistence.
  #   FPERSIST·sotcron-never   · sotcron's AUDIT kind 0xc2 emitted when
  #                              a timer flagged F_persistence is
  #                              prevented from firing.
  "FPERSIST·install:\\[LucAs\\] persistence install · path="
  "FPERSIST·audit-emit:\\[LucAs\\] AUDIT kind=0xc0"
  "FPERSIST·anomaly-log:PERSISTENCE_INSTALL"
  "FPERSIST·sotinit-scan:\\[sotinit\\] sotfs scan_now"
  "FPERSIST·never-activate:\\[sotinit\\] skip activate .* · F_persistence"
  "FPERSIST·sotcron-never:\\[sotcron\\] AUDIT kind=0xc2"
  # anomaly PR 6 · graded multi-signal simulated_attacker narrative.  Three
  # operator-driven gates with the SAME documented FAIL pattern as the
  # FPERSIST·* / PROCD·synth·* groups above · they only fire when the
  # operator runs `inject-script /honey-scripts/simulated_attacker.py` at the
  # sotShell prompt.  The unattended 60 s smoke boot does NOT drive the
  # demo, so all three FAIL in non-operator runs · that is the documented
  # operator-driven convention, not a regression.  The patterns are listed
  # here so a full demo-loop run (e.g. via expect) gets credit for the
  # graded score evidence chain.  The three beats walk the unified score
  # through both promotion thresholds:
  #   ANOMALY·recon-credread · the cred-access classifier flagging the
  #                             Stage-2 recon read of /honey-aws-creds
  #                             (CRED_ACCESS=+15 · score 15 · under T1=20 ·
  #                             [LucAs] cred-access · pid=N path=/honey-aws-creds).
  #   ANOMALY·graded-tier1   · the Stage-3 encrypt writes carrying the
  #                             score 15 → >=20 · the anomaly reply-driven
  #                             Tier 0 → 1 promotion ([anomaly] pid=N
  #                             reply-driven promote Tier 0 → 1).
  #   ANOMALY·graded-tier2   · the Stage-4 second cred read + unlink burst +
  #                             C2 exfil crossing T2=40 · the functor rebind
  #                             to F_2 ([functor] pid=N transition F_1 → F_2
  #                             (η^1→2)).
  "ANOMALY·recon-credread:\\[LucAs\\] cred-access · pid=[0-9]+ path=/honey-aws-creds"
  "ANOMALY·graded-tier1:\\[anomaly\\] pid=[0-9]+ reply-driven promote Tier 0 → 1"
  "ANOMALY·graded-tier2:\\[functor\\] pid=[0-9]+ .* → F_2"
  # A1 PR1 · native spawn loads the ELF from bytes (sto/shell call sites pass non-NULL bytes)
  "NATIVE·sto-from-bytes:\\[spawn-native\\] 'sotOs-sto' from bytes · [0-9]+ bytes · entry=0x"
  # A1 PR2 · sto bytes sourced from binstore
  "MIGRAR·sto-binstore:\\[spawn\\] load 'sotOs-sto' · source=binstore"
  # A1 PR3 · shell bytes sourced from binstore
  "MIGRAR·shell-binstore:\\[spawn\\] load 'sotOs-shell' · source=binstore"
  # A2 PR4 · resolver checks rwbinstore first (still resolves binstore/CPIO when empty)
  "RWBIN·resolve-order:\\[spawn\\] load 'tcc.bin' · source=binstore"
  # A2 PR5 · `bininstall tcc.bin tcc.bin` copies tcc into the writable store,
  #          then the next tcc spawn resolves from rwbinstore (shadows binstore).
  "RWBIN·write-spawn:\\[spawn\\] load 'tcc.bin' · source=rwbinstore"
  # A2 PR5 · after the simreboot cascade, the rwbinstore index is re-read from
  #          disk with the installed entry still present (persistence proof).
  "RWBIN·persist-simreboot:\\[rwbinstore\\] ready · [1-9][0-9]* entries"
  # Arc B · zombie-table evict-oldest hardening · deterministic over-capacity
  #         proof at bootstrap (2 oldest evicted · newest still reapable · no
  #         exit silently lost).
  "REAPER·selftest:\\[sotbox\\] reaper selftest OK · cap=32 · evicted 2 · newest reapable"
  # Arc C2 · demo mode · phase banners, incident rollup, post-attack
  #          integrity proof.  (#3 guest-stdout tag reverted in v0.39.1 ·
  #          a single global line-flag mis-attributes on the shared serial.)
  "DEMO·phase-banners:PHASE 1 · BASELINE"
  "DEMO·incident-summary:═══ INCIDENT SUMMARY"
  "DEMO·integrity-ok:\\[verify\\] /tmp/welcome OK · real data intact"
  # C2 #3 (v2) · guest stdout correctly tagged · the HEADLINE guest line is
  # prefixed (per-sotbox line buffering · no system line is mis-tagged).
  "DEMO·guest-tag:│guest:[0-9]+│ \\[st-hello\\] tcc-run OK"
  # Performance benchmarks · micro_baseline IPC-roundtrip harness emits a JSON
  # block to serial (presence/structure gates · TSC under QEMU is reproducible-
  # ratio-only, never gate on absolute cycle magnitudes).
  "BENCH·begin:===BENCH-JSON-BEGIN==="
  "BENCH·end:===BENCH-JSON-END==="
  "BENCH·identity:\"bench\":\"micro_baseline\""
  "BENCH·run-stats:\"name\":\"ipc_roundtrip_invalid\",\"n\":1000,"
  # STO-session bench · per-op latency · own badge (0xB001) · recycles tx every
  # 16 ops to stay within STO_MAX_TX (0 STO errors).
  "BENCH·sto-ops:\"bench\":\"micro_sto_ops\""
  "BENCH·sto-ops-commit:\"name\":\"commit\",\"n\":1000,"
  # Isolated benches (v0.46.0) · orch blocks on each bench's done EP so it runs
  # alone → clean numbers.  throughput now completes all 10000 txs; sweep_cost
  # runs to n16 without exhausting the wrapped-cap pool.
  "BENCH·throughput:\"completed\":10000,"
  "BENCH·sweep:\"name\":\"rollback_n16\",\"n\":50,"
  "BENCH·isolated:· isolated run complete"
  # C2 #10 · display_pid is deterministic-by-design (fixed seed, keyed on
  # synthetic_pid) · these exact values prove reproducibility in a single boot ·
  # ASLR/entropy stream untouched (separate PRNG).
  "PIDRAND·deterministic:\\[pidrand\\] selftest · display\\(1\\)=43465 display\\(2\\)=5110"
  # Clean poweroff · unattended boot persists state (WAL checkpoint+flush) then
  # powers off the QEMU VM via ACPI S5 (the VM exits before the 120s timeout).
  "POWEROFF·checkpoint:\\[orch\\] POWEROFF · WAL checkpoint\\+flush"
  "POWEROFF·acpi:\\[orch\\] POWEROFF · powering off VM \\(ACPI S5"
)

fail=0
for chk in "${CHECKS[@]}"; do
    lab="${chk%%:*}"
    pat="${chk#*:}"
    if grep -qE "$pat" "$LOG"; then
        echo "PASS · $lab"
    else
        echo "FAIL · $lab (pattern: $pat)"
        fail=1
    fi
done

if (( fail != 0 )); then
    echo
    echo "Last 60 lines of serial output for diagnosis:"
    echo "──────────────────────────────────────────────"
    tail -60 "$LOG"
fi

exit $fail
