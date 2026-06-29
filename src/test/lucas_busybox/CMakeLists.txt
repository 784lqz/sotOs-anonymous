set(LUCAS_BUSYBOX_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/busybox-static.bin"
    CACHE FILEPATH "Path to the pre-built Alpine static busybox"
    FORCE)

if(NOT EXISTS "${LUCAS_BUSYBOX_BIN}")
    message(WARNING "lucas_busybox: ${LUCAS_BUSYBOX_BIN} not found · run rebuild per README.md")
endif()
