# sotOs · L10 · PTY test fixture · pre-built static x86_64 ELF.
# Calls open("/dev/ptmx") + write + open("/dev/pts/0") + read + write(2) + exit_group.
# No libc, no PT_INTERP · fits in orch allocman pool.
#
# Rebuild:
#   cd src/test/lucas_pty_test
#   gcc -nostdlib -static -no-pie -Wl,--build-id=none -o pty_test.bin pty_test.S
#   strip pty_test.bin

set(LUCAS_PTY_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/pty_test.bin"
    CACHE FILEPATH "Path to the pre-built PTY test fixture ELF"
    FORCE)

if(NOT EXISTS "${LUCAS_PTY_TEST_BIN}")
    message(WARNING "lucas_pty_test: ${LUCAS_PTY_TEST_BIN} not found · rebuild per comment above")
endif()
