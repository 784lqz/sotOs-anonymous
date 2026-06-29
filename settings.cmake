# sotOs · seL4 build settings
# Loaded by CMake via -C settings.cmake at configure time.

# Architecture & platform
set(KernelArch          "x86"   CACHE STRING "")
set(KernelSel4Arch      "x86_64" CACHE STRING "")
set(KernelX86Sel4Arch   "x86_64" CACHE STRING "")
set(KernelPlatform      "pc99"  CACHE STRING "")
# Build the kernel for a GENERIC x86_64 baseline (not a specific microarch).  The
# honeypot image must boot on varied hosts / QEMU CPU models; with a specific
# microarch, seL4's is_compiled_for_microarchitecture() hits its default case for
# any CPU model newer than its table (typical under `-cpu host` on a modern host)
# and prints "Warning: Your kernel was not compiled for the current
# microarchitecture." on boot.  generic → that check always passes → no warning,
# and the image is portable. (boot_sys.c:328 · default returns false unless GENERIC.)
set(KernelX86MicroArch  "generic" CACHE STRING "" FORCE)

# Debug builds: enable kernel printf + debug putchar (serial 0x3f8)
set(KernelDebugBuild           ON  CACHE BOOL "")
set(KernelPrinting             ON  CACHE BOOL "")
set(KernelVerificationBuild    OFF CACHE BOOL "")

# sotOs ADR-005: disable KernelSkimWindow (Meltdown mitigation) so the
# Linux ABI compatibility patch (save user RSP on syscall trap) can
# write to kernel data from the syscall entry path. Without SKIM, the
# kernel address space is mapped in user CR3 too, so the save works.
# This is a dev-build tradeoff · production builds for Meltdown-vulnerable
# CPUs need a proper trampoline-page solution.
set(KernelSkimWindow           OFF CACHE BOOL "")

# Build a Tickless/fast scheduler suitable for QEMU
set(KernelMaxNumNodes          "1"   CACHE STRING "")
set(KernelOptimisation         "-O2" CACHE STRING "")

# Userland: enable libc support
set(LibSel4MuslcSys            ON  CACHE BOOL "")
set(LibSel4DebugFunctionInstrumentation OFF CACHE BOOL "")

# Image generation
set(KernelRootCNodeSizeBits    "16" CACHE STRING "") # 13→16 (8K→64K slots) for L11-β-2 CPython embed · root needs ~6500 frame caps for 26 MiB orch.elf

# sotOs PY7: gated kernel-side diagnostic trace at the iretq/sysretq return
# paths.  When ON the kernel prints [k:iretq]/[k:sysrt] lines whenever the
# next user RIP lies in Python's high text segment (0x12000000..0x12200000).
# Default OFF so smoke runs see no extra output.  The compile-time toggle is
# wired up in the outer CMakeLists.txt (add_compile_definitions) so a stale
# build dir is enough to pick up a flag flip; no kernel-source edit needed.
set(KernelLucAsTrace           OFF CACHE BOOL
    "Enable [k:iretq]/[k:sysrt] kernel trace for the LucAs Python-text-range")

# sotOs VFS-FS-TRACE: gated user-side trace at LucAs's fs syscall boundary.
# When ON, LucAs_sys_{open,openat,read,fstat} emit [fs] ... lines so the
# operator can diagnose VFS interactions (e.g. Python's import-path probes,
# mmap-backed file reads, stub fstat results).  Default OFF so smoke runs
# see no extra output and the printf call sites compile to no-ops.  The
# toggle is propagated to compile defs in the outer CMakeLists.txt
# (mirror of KernelLucAsTrace).
set(KernelLucAsFsTrace         OFF CACHE BOOL
    "Enable verbose LucAs fs syscall tracing")

# sotOs OBSD-eta · enable Intel Memory Protection Keys (MPK / PKU) support
# in the seL4 kernel.  When ON this enables step 1 of the 5-step kernel
# patch described in docs/obsd-zeta-mpk-design.md: CR4.PKE is set at boot
# (gated by CPUID.7.0.ECX bit 3) so unprivileged RDPKRU/WRPKRU no longer
# fault with #UD.  The remaining steps (PTE bitfield widening, cap
# invocation, per-thread PKRU save/restore) are documented as a .patch
# file at docs/patches/obsd-eta-mpk-seL4.patch and require a separate
# bitfield-regeneration workflow (see tools/apply-mpk-patch.sh).
#
# DEFAULT OFF.  Toggling ON forks the verified seL4 chain · this is a
# documented best-effort-verified deviation, see ADR in obsd-zeta-mpk-design.md.
set(KernelLucAsMPK             OFF CACHE BOOL
    "Enable Intel MPK (OBSD-eta · requires seL4 kernel patch)")

# Networking egress stack (lwIP spike) · mature TCP/IP for OUTBOUND connections
# (apk/apt/pip), replacing the hand-rolled δ busy-poll stack for egress.  The δ
# stack stays for inbound deception (crafted Linux SYN-ACK/JA3S fingerprint).
# liblwip is the seL4 glue; LWIP_PATH points at the upstream stack (external/lwip).
# libethdrivers (virtio_pci) + libplatsupport (timers) build as plain targets.
set(LibLwip          ON  CACHE BOOL "")
set(LWIP_PATH        "${CMAKE_CURRENT_LIST_DIR}/external/lwip" CACHE STRING "")
