# sotOs · sotnano gap-buffer unit test ELF.
#
# Spawned by root at boot.  Exercises the freestanding gap-buffer ops
# (insert/delete/move/serialize/cursor_rowcol) from src/sotshell/sotnano.c.
# Prints PASS/FAIL lines that scripts/smoke-procd.sh greps from the QEMU
# serial log.  Mirrors src/test/sotOs-wal-unit/.
add_executable(sotOs-sotnano-unit
    main.c
    ${CMAKE_SOURCE_DIR}/src/sotshell/sotnano.c)

target_include_directories(sotOs-sotnano-unit PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/sotshell)

target_link_libraries(sotOs-sotnano-unit
    sotos-string
    sel4
    muslc
    sel4muslcsys
    sel4debug
    utils)
