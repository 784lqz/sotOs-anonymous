# sotNet-β-4 · UDP send fixture · pre-built static x86_64 ELF.
# Calls socket(AF_INET, SOCK_DGRAM, 0) + sendto(10.0.2.2:9999) + exit_group.
# No libc, no PT_INTERP · ~4.5 KiB stripped · fits in orch allocman pool.
#
# Rebuild:
#   cd src/test/lucas_udp_send
#   gcc -nostdlib -static -no-pie -Wl,--build-id=none -o udp_send.bin udp_send.S
#   strip udp_send.bin

set(LUCAS_UDP_SEND_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/udp_send.bin"
    CACHE FILEPATH "Path to the pre-built UDP send fixture ELF"
    FORCE)

if(NOT EXISTS "${LUCAS_UDP_SEND_BIN}")
    message(WARNING "lucas_udp_send: ${LUCAS_UDP_SEND_BIN} not found · rebuild per comment above")
endif()
