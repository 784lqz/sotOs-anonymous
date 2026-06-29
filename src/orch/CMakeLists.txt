include(${CMAKE_SOURCE_DIR}/tools/cmake-tool/helpers/cpio.cmake)

# Bundle child binaries into orch's own CPIO archive so sotbox_spawn
# can locate them via cpio_get_file at runtime.
# busybox-static.bin: L2 regression demo.
# fork_test.bin: L3a fork+wait4 end-to-end demo.
# L4: sotOs-shell in orch's CPIO.  Orch spawns it via ORCH_OP_SPAWN_NATIVE
# after Linux demos complete.  Orch has its own delegated untypeds so this
# doesn't drain root's VKA budget.
set(ORCH_CHILD_BINS "${LUCAS_FORK_TEST_BIN}"
    "${LUCAS_UDP_SEND_BIN}"
    "${LUCAS_PTHREAD_BIN}"
    "${LUCAS_ARCH_PRCTL_BIN}"
    # PR 6 · procd fork/exit/wait4 smoke fixture.
    "${PROCD_FORK_TEST_BIN}"
    # PR 9 · procd setsid/setpgid/getpgid smoke fixture.
    "${PROCD_PG_TEST_BIN}"
    # PR 12 · futex WAIT_BITSET / WAKE_BITSET broadcast smoke fixture.
    "${PROCD_COND_TEST_BIN}"
    # PR 13 · set_robust_list + thread-exit robust walk smoke fixture.
    "${PROCD_ROBUST_TEST_BIN}"
    # init-cron PR 10 · lucas shellhook execve argv-rewrite fixture.
    "${SHELLHOOK_TEST_BIN}"
    # γ · Stage 7 · F_persistence end-to-end fixture (C-static; the
    # Python simulated_attacker.py path can't run today because the
    # python312 stdlib zip is not populated in the install image).
    "${STAGE7_DEMO_BIN}"
    # POSIX-surface PR 6 · syscall-test fixture (unlink/iov/madvise +
    # console/FS boundary · validates PRs 1-5 at runtime).
    "${SYSCALL_TEST_BIN}"
    # T5 · syscall-latency microbench (raw getpid under rdtsc) · measures the
    # fault→IPC→lucAs→return cost vs a native baseline.  Static musl ELF kept in
    # src/orch/ (a sibling path: projects/sotOs/orch is a symlink to src/orch, so a
    # ../-relative path off it resolves through the symlink and overshoots).
    "${CMAKE_CURRENT_SOURCE_DIR}/ubench.bin"
    # ANOMALY PR 7 · weighted-score test fixture · drives a sotbox's
    # suspicion score across T1/T2 (cred + writes + unlink burst) ·
    # always-on regression proof of the anomaly PR 1-5 scoring engine.
    "${ANOMALY_TEST_BIN}"
    # SP1 PR 4 · writable-executable-memory test fixture · proves a TRUSTED
    # sotbox can execute memory it mapped RWX (the gating capability for the
    # in-OS C compiler's code generation).  Always-on regression proof of the
    # W^X relaxation for st->trusted.
    "${EXECMAP_TEST_BIN}"
    # sotNet γ-3-γ-2b · BearSSL TLS client fixture (basename tls_probe.bin).
    "${TLS_PROBE_BIN}"
    # L12-beta · AF_UNIX wayland-0 route fixture.
    "${WAYLAND_CONNECT_BIN}"
    # L12-gamma · wl_display.sync round-trip fixture.
    "${WAYLAND_SYNC_BIN}"
    # L12-delta · wl_registry globals + bind fixture.
    "${WAYLAND_INFO_BIN}"
    # L13-D1 · hand-rolled wl_shm zero-copy pixel client fixture.
    "${WL_SHM_BIN}"
    # L14a-D1 · hostile screen-capture client fixture (Tier-2 infostealer sim).
    "${WL_CAPTURE_CLIENT_BIN}"
    # L14a · baked Canary Screenshot asset (GNOME+Files BGRA 256x192).
    "${CANARY_DESKTOP_RGBA}"
    # L14b · baked xkb_v1 keymap asset (us layout).
    "${KEYMAP_US_XKB}"
    # N1a · real-egress probe fixture.
    "${EGRESS_PROBE_BIN}"
    # sottrace-v1 · T10 · canary-service listen/accept/recv fixture.
    "${CANARY_SERVICE_BIN}"
    # sottrace-v1 · T11 · canary-read Tier-2 fixture (exercises trace_emit_canary).
    "${CANARY_READ_BIN}"
    # Pillar-2 P2a · churn-harness fixture (basename hello-linux.bin) · the
    # trivial L1 static-Linux ELF cmd_churn spawns in a tight loop to measure
    # the per-spawn capability leak (baseline before the teardown fix).
    "${LUCAS_HELLO_BIN}"
    # Pillar-2 P2b · fork-bomb gate fixture (basename fork_bomb.bin) · a static
    # ELF that raw-fork()s in a tight loop past SOTBOX_FORK_QUOTA to drive the
    # anti-DoS quarantine + terminate path.
    "${LUCAS_FORK_BOMB_BIN}"
    # Pillar-3 sottrace-Pro · anti-debug invisibility probe (basename
    # antidbg_probe.bin) · a static ELF that calls ptrace(TRACEME) + reads
    # /proc/self/status's TracerPid + getppid and prints an invisible=YES/NO
    # verdict · drives the black-box anti-ptrace invisibility cert.
    "${LUCAS_ANTIDBG_BIN}"
    # vDSO arc · Task 5 · F1 · boot probe: parses the mapped vDSO ELF manually
    # (Ehdr→PT_LOAD→load_bias→PT_DYNAMIC→DT_SYMTAB/HASH/GNU_HASH), resolves
    # __vdso_clock_gettime by name, calls it for CLOCK_MONOTONIC + CLOCK_REALTIME,
    # and emits "[vdso-probe] resolved=0x... mono=... real=..." as the gate marker.
    # Use CMAKE_SOURCE_DIR (repo root) — avoids the symlink-overshoot issue of
    # relative ../-paths from the build-side src/orch CMakeLists.txt.
    "${CMAKE_SOURCE_DIR}/tools/eval/t5-syscall/vdso_probe.bin"
    # vDSO arc · Task 8 · libc bench: normal musl-linked binary that calls
    # clock_gettime() via the standard libc entry point.  musl resolves
    # __vdso_clock_gettime from AT_SYSINFO_EHDR automatically.  Emits:
    #   [ubench-libc] clock_gettime min=<cyc> mean=<cyc>
    # Gate asserts min < 1000 (no trap — real vDSO fast-path).
    "${CMAKE_SOURCE_DIR}/tools/eval/t5-syscall/ubench_libc.bin"
    # fast-path arc · Task 9 · sched_yield fast-path gate probe: calls
    # sched_yield (sysno 24) in a timed lfence;rdtsc loop, emits:
    #   [fastpath-probe] sched_yield_cycles=<min> ret=<ret>
    # Gate asserts min < 2000 (fast-path, no seL4_Yield IPC) and ret==0.
    "${CMAKE_SOURCE_DIR}/tools/eval/t5-syscall/fastpath_probe.bin"
    # Performance benchmarks · spawned via ORCH_OP_SPAWN_BENCH.  micro_baseline
    # gets orch's badged 0xA003 STO EP (ping); the three STO-session harnesses
    # each get a distinct per-bench badge minted from the unbadged listen EP.
    # CPIO entry basenames resolved by spawn_load_elf as "sotOs-bench_<name>".
    "$<TARGET_FILE:sotOs-bench_baseline>"
    "$<TARGET_FILE:sotOs-bench_sto_ops>"
    "$<TARGET_FILE:sotOs-bench_throughput>"
    "$<TARGET_FILE:sotOs-bench_sweep_cost>")
    # SP2 PR4 · TCC migrated out of orch's CPIO into the sotfs binstore region.
    # tcc.bin is now resolved at runtime via spawn_load_elf (binstore-first), so
    # the CPIO copy is removed to drop ~414 KiB from orch.elf.
# L11-β-2 · CPython 3.12 static (24 MiB) embedded · pair this with the
# ALLOCATOR_STATIC_POOL_SIZE bump in src/root/bootstrap.c to handle the
# 26 MiB orch.elf at root load time.
# PY4 · arch_prctl_test.bin is a ~4.5 KiB asm isolator for the Python
# `entry+2` mystery (see src/test/lucas_arch_prctl).
MakeCPIO(orch_archive.o "${ORCH_CHILD_BINS}"
    DEPENDS "${LUCAS_FORK_TEST_BIN}"
            "${LUCAS_UDP_SEND_BIN}"
            "${LUCAS_PTHREAD_BIN}"
            "${LUCAS_ARCH_PRCTL_BIN}"
            "${PROCD_FORK_TEST_BIN}"
            "${PROCD_PG_TEST_BIN}"
            "${PROCD_COND_TEST_BIN}"
            "${PROCD_ROBUST_TEST_BIN}"
            "${SHELLHOOK_TEST_BIN}"
            "${STAGE7_DEMO_BIN}"
            "${SYSCALL_TEST_BIN}"
            "${ANOMALY_TEST_BIN}"
            "${EXECMAP_TEST_BIN}"
            "${TLS_PROBE_BIN}"
            "${WAYLAND_CONNECT_BIN}"
            "${WAYLAND_SYNC_BIN}"
            "${WAYLAND_INFO_BIN}"
            "${WL_SHM_BIN}"
            "${WL_CAPTURE_CLIENT_BIN}"
            "${CANARY_DESKTOP_RGBA}"
            "${KEYMAP_US_XKB}"
            "${EGRESS_PROBE_BIN}"
            "${CANARY_SERVICE_BIN}"
            "${CANARY_READ_BIN}"
            "${LUCAS_HELLO_BIN}"
            "${LUCAS_FORK_BOMB_BIN}"
            "${LUCAS_ANTIDBG_BIN}"
            "$<TARGET_FILE:sotOs-bench_baseline>"
            "$<TARGET_FILE:sotOs-bench_sto_ops>"
            "$<TARGET_FILE:sotOs-bench_throughput>"
            "$<TARGET_FILE:sotOs-bench_sweep_cost>")

# vDSO arc · Task 4 · embed the freestanding PIC vdso.so (built by src/vdso/,
# add_subdirectory'd BEFORE orch) into the orchestrator image via .incbin —
# mirroring the children_archive/orch_archive CPIO embed (MakeCPIO above).  The
# generated vdso_blob.o exports _sotos_vdso_blob_start/_end; src/orch/vdso_map.c
# memcpy's these bytes into each guest vspace at SOTOS_VDSO_BASE+0x1000.
if(DEFINED SOTOS_VDSO_SO)
    set(VDSO_SO "${SOTOS_VDSO_SO}")
else()
    set(VDSO_SO "${CMAKE_BINARY_DIR}/images/vdso.so")
endif()
separate_arguments(vdso_c_flags_sep NATIVE_COMMAND "${CMAKE_C_FLAGS}")
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    list(APPEND vdso_c_flags_sep "${CMAKE_C_COMPILE_OPTIONS_TARGET}${CMAKE_C_COMPILER_TARGET}")
endif()
add_custom_command(
    OUTPUT vdso_blob.o
    COMMAND
        sh -c
        "echo 'X.section ._vdso_blob,\"a\"X.globl _sotos_vdso_blob_start, _sotos_vdso_blob_endX_sotos_vdso_blob_start:X.incbin \"${VDSO_SO}\"X_sotos_vdso_blob_end:X' | tr X '\\n' > vdso_blob.S"
    COMMAND
        ${CMAKE_C_COMPILER} ${vdso_c_flags_sep} -c -o vdso_blob.o vdso_blob.S
    DEPENDS "${VDSO_SO}" sotos-vdso
    VERBATIM
    BYPRODUCTS vdso_blob.S
    COMMENT "Embed vdso.so into orch (vdso_blob.o · .incbin)"
)

add_executable(sotOs-lucas-orch main.c bootstrap.c arena.c spawn.c spawn_native.c sotbox_table.c fork.c fault_loop.c execve.c pipe.c backends_sotnet.c tpm.c sotguard_pump.c procd_client.c simreboot.c shm_pool.c canary_screenshot.c keymap.c virtio_gpu.c console_fb.c fb_blit.c virtio_input.c virtio_mouse.c fs_gate_selftest.c lwip_egress.c serial_aux.c vdso_map.c orch_archive.o vdso_blob.o
    ${CMAKE_SOURCE_DIR}/src/sotfs/storage_virtio_blk.c
    ${CMAKE_SOURCE_DIR}/src/sotfs/storage_virtio_net.c
    ${CMAKE_SOURCE_DIR}/src/sotfs/virtio_pci_modern.c
    # PR 6 · per-subsystem WAL replay-applies · procd path needs
    # procd/proc.h (which transitively pulls autoconf via sel4/sel4.h)
    # so it builds inside orch's autoconf-aware translation unit set.
    # replay_anomaly.c + replay_sotnet.c live in sotos-sotfs (no
    # autoconf deps); only replay_procd.c lives here.
    ${CMAKE_SOURCE_DIR}/src/sotfs/replay_procd.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/dhcp.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/sotnet.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/synth.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/dns.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/tcp.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/tcp_fp.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/tcp_server.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/tcp_client.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/tcp_data.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/tcp_close.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/tcp_timer.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/tcp_audit.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/ipv6.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/arp.c
    ${CMAKE_SOURCE_DIR}/src/sotnet/route.c)
# virtio-blk Phase 2b · compile the PCI discovery source at -Os alongside
# the other sotfs storage files.  It needs seL4 syscall headers which orch
# already has via target_link_libraries(... sel4 ...).
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotfs/storage_virtio_blk.c
    PROPERTIES COMPILE_FLAGS "-Os")
# PR 6 · procd WAL replay-applies · same -Os discipline as the rest of
# the sotfs source set.  Keeps the orch.elf text section budget intact.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotfs/replay_procd.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet-β-1 · virtio-net PCI discovery at -Os alongside virtio-blk.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotfs/storage_virtio_net.c
    PROPERTIES COMPILE_FLAGS "-Os")
# virtio-modern · PCI cap-chain + BAR map + negotiate + virtqueue + request/poll.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotfs/virtio_pci_modern.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet-β-3 · minimal ARP/ICMP stack.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/sotnet.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · N1 · DHCP client.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/dhcp.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet-γ Phase 2 · Synth Internet stub.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/synth.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet-ε Phase 1 · DNS deception canary domain table.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/dns.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · N2 · TCP-RST visibility responder.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/tcp.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · arc β · pure TCP/IP fingerprint logic (leaf module).
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/tcp_fp.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · T1 · TCP server-side 3-way handshake.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/tcp_server.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · T2 · TCP client-side 3-way handshake.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/tcp_client.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · T3 · TCP data path (send + recv + ACK).
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/tcp_data.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · T4 · TCP close path (FIN exchange).
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/tcp_close.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · T5 · TCP retransmission timer (strong tcp_timer_tick override).
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/tcp_timer.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · T8 · TCP_OPEN anomaly audit hook (strong override of tcp_audit_open).
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/tcp_audit.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · N3 · IPv6 + ICMPv6 echo + Neighbor Solicitation.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/ipv6.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet · N5 · ARP cache (LRU 16, 5min TTL).
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/arp.c
    PROPERTIES COMPILE_FLAGS "-Os")
# sotNet N4 · routing table + default gateway.
set_source_files_properties(${CMAKE_SOURCE_DIR}/src/sotnet/route.c
    PROPERTIES COMPILE_FLAGS "-Os")

target_include_directories(sotOs-lucas-orch PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

# Phase 1b · fs-gate self-test gating.  src/orch/fs_gate_selftest.c is a NO-OP
# unless SOTOS_FS_GATE is defined: the heavy 50 MiB write + simreboot persist
# leg (thousands of virtio-blk ops) must NOT run in the normal boot path or it
# would slow/timeout the clock/git/glibcdyn/tui gates.  Only tools/fs-gate.sh
# reconfigures with -DSOTOS_FS_GATE=ON; every other build leaves it OFF (the
# default) and links an empty fs_gate_selftest().
option(SOTOS_FS_GATE "Compile the Phase 1b 50 MiB fs-gate boot self-test" OFF)
if(SOTOS_FS_GATE)
    target_compile_definitions(sotOs-lucas-orch PRIVATE SOTOS_FS_GATE=1)
    message(STATUS "sotOs · SOTOS_FS_GATE=ON · orch boots the 50 MiB fs self-test")
endif()

target_link_libraries(sotOs-lucas-orch
    sotos-string
    sotos-sotguard
    sotos-sottrace
    sotos-procd-lib    # PR 4 · procd_event_drain for the procd→orch NTF channel
    sotOs-lucas
    sel4
    muslc
    sel4muslcsys
    sel4platsupport
    sel4simple
    sel4simple-default
    sel4allocman
    sel4vka
    sel4utils
    sel4debug
    utils
    cpio
    # lwIP egress spike · mature TCP/IP for outbound (apk/apt/pip).  liblwip stack
    # + libethdrivers virtio_pci driver + the lwIP netif glue + util_libs platsupport.
    lwip
    ethdrivers
    platsupport
    sotos-sotguard)      # SG-NET Phase 2 · sotGuard event-bus producers
