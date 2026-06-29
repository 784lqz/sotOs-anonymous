# sotlibc · the freestanding C runtime for world-#3 NATIVE sotOs binaries.
#
# NOT a Linux libc.  The third world (sotOs-native · sotctl) knows it is on
# sotOs and talks sotabi to truth-core — it does not pretend to be Linux
# (LUCAS/muslc) or Win32 (Wine).  sotlibc supplies only the minimal C runtime
# such a binary needs: mem/string/parse/format + serial output, NOTHING ELSE.
#
#   sotlibc.c         · pure, host-unit-testable (mem/str/strtoul/printf engine)
#   sotlibc_serial.c  · seL4-only sink (sot_putchar/sot_printf → seL4_DebugPutChar)
#
# Under -nostdinc the muslc target supplies the freestanding <stdint.h>/<stddef.h>/
# <stdarg.h> headers (NO muslc symbols are pulled — sotlibc defines its own).
set(SOTLIBC_SOURCES
    sotlibc.c
    sotlibc_serial.c
)

add_library(sotlibc STATIC ${SOTLIBC_SOURCES})

target_include_directories(sotlibc PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotlibc
    sel4
    sel4_autoconf
    muslc)

# Keep the .a small so the native binary stays lean in the CPIO image.
set_source_files_properties(${SOTLIBC_SOURCES}
    PROPERTIES COMPILE_FLAGS "-Os")
