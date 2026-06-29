add_executable(sotOs-net-synth main.c response_profiles.c tls_rng.c tls_selftest.c inbound_http.c ssh_wire.c ssh_transport.c tls13_wire.c tls13_keysched.c tls13_aead.c tls13.c tls13_sign.c
    sntrup761/sntrup761.c sntrup761_glue.c   # SSH HASSH arc · sntrup761x25519-sha512 hybrid KEX
    poly1305/poly1305.c                      # SSH HASSH arc · chacha20-poly1305@openssh.com
    ${CMAKE_SOURCE_DIR}/src/lucas/tty_session.c)  # Task B2 · pure winsize decoders (no orch deps)

# the vendored sntrup761.c is gated by USE_SNTRUP761X25519 (OpenSSH's #ifdef)
set_source_files_properties(sntrup761/sntrup761.c PROPERTIES COMPILE_DEFINITIONS USE_SNTRUP761X25519)

target_include_directories(sotOs-net-synth PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/external/bearssl/inc)

target_link_libraries(sotOs-net-synth
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils
    bearssl)
