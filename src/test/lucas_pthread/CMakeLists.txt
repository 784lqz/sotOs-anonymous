# MS-M2 · pthread (clone+futex) fixture · pre-built static x86_64 ELF.
# Exercises clone(CLONE_VM | CLONE_THREAD | CLONE_SETTLS) + futex
# WAIT/WAKE on a shared global.  Exit code = shared_var observed by
# parent (expected 42).
# No libc, no PT_INTERP · ~1 KiB stripped · fits in orch allocman pool.
#
# Rebuild:
#   cd src/test/lucas_pthread
#   gcc -nostdlib -static -no-pie -Wl,--build-id=none -o pthread_test.bin pthread_test.S
#   strip pthread_test.bin

set(LUCAS_PTHREAD_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/pthread_test.bin"
    CACHE FILEPATH "Path to the pre-built pthread test fixture ELF"
    FORCE)

if(NOT EXISTS "${LUCAS_PTHREAD_BIN}")
    message(WARNING "lucas_pthread: ${LUCAS_PTHREAD_BIN} not found · rebuild per comment above")
endif()
