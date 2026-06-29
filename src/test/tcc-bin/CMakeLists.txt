# Prebuilt-and-committed TinyCC binary (same pattern as syscall_test.bin /
# anomaly_test.bin).  The build embeds it · it does not compile TCC.
# Provenance + rebuild recipe in VENDOR.md.
set(TCC_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/tcc.bin"
    CACHE FILEPATH "Path to the pre-built static TinyCC binary"
    FORCE)

if(NOT EXISTS "${TCC_BIN}")
    message(WARNING
        "tcc-bin: ${TCC_BIN} not found · rebuild per VENDOR.md")
endif()
