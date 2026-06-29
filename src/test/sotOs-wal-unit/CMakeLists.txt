# sotOs · WAL unit test ELF.
#
# Spawned by root at boot.  Exercises the CRC64 implementation and
# v2 payload struct sizes against the public ABI in <sotfs/wal.h> +
# <sotfs/crc64.h>.  Prints PASS/FAIL lines that scripts/smoke-procd.sh
# greps from the QEMU serial log.  Mirrors src/test/procd_unit/.
add_executable(sotOs-wal-unit main.c)

target_include_directories(sotOs-wal-unit PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(sotOs-wal-unit
    sotos-sotfs
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)
