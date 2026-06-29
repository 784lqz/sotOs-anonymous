# sotOs · PY4 · arch_prctl reproducer fixture · pre-built static x86_64 ELF.
# Minimal isolator for the Python `entry+2` mystery: reproduces the
# `syscall ; ret` pattern that crashes CPython's musl __set_thread_area
# in a ~100-byte static ELF.  See arch_prctl_test.S for details.
#
# No libc, no PT_INTERP · negligible orch allocman pool cost.
#
# Rebuild:
#   cd src/test/lucas_arch_prctl
#   gcc -nostdlib -static -no-pie -fno-pie -Wl,--build-id=none \
#       -o arch_prctl_test.bin arch_prctl_test.S
#   strip arch_prctl_test.bin

set(LUCAS_ARCH_PRCTL_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/arch_prctl_test.bin"
    CACHE FILEPATH "Path to the pre-built arch_prctl test fixture ELF"
    FORCE)

if(NOT EXISTS "${LUCAS_ARCH_PRCTL_BIN}")
    message(WARNING "lucas_arch_prctl: ${LUCAS_ARCH_PRCTL_BIN} not found · rebuild per comment above")
endif()
